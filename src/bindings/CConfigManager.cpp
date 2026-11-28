#include "CConfigManager.h"
#include "common/KestrelBinaryReader.h"
#include "common/KestrelCrypto.h"
#include "common/KestrelUtf8.h"
#include "../diagnostics/CrashAndTelemetry.h"
#include "../assets/BtDecryptHook.h"

#include <algorithm>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <mutex>
#include <set>
#include <string_view>
#include <vector>

USING_NS_CC;
namespace fs = std::filesystem;

namespace {

std::recursive_mutex g_configSqliteMutex;
std::set<sqlite3_stmt*> g_busyStatements;

struct StmtFinalizeGuard {
    sqlite3_stmt* stmt = nullptr;
    explicit StmtFinalizeGuard(sqlite3_stmt* s) : stmt(s) {}
    ~StmtFinalizeGuard() {
        if (stmt) sqlite3_finalize(stmt);
    }
    StmtFinalizeGuard(const StmtFinalizeGuard&) = delete;
    StmtFinalizeGuard& operator=(const StmtFinalizeGuard&) = delete;
};

struct StmtExecutionScope {
    sqlite3_stmt* stmt = nullptr;
    bool ownsTempStmt = false;

    StmtExecutionScope(sqlite3* db, sqlite3_stmt* cachedStmt, const std::string& fallbackSql) {
        if (cachedStmt && g_busyStatements.find(cachedStmt) == g_busyStatements.end()) {
            stmt = cachedStmt;
            g_busyStatements.insert(stmt);
            sqlite3_reset(stmt);
            sqlite3_clear_bindings(stmt);
        } else if (db && !fallbackSql.empty()) {
            sqlite3_stmt* tmp = nullptr;
            if (sqlite3_prepare_v2(db, fallbackSql.c_str(), -1, &tmp, nullptr) == SQLITE_OK && tmp) {
                stmt = tmp;
                ownsTempStmt = true;
                g_busyStatements.insert(stmt);
            }
        }
    }

    ~StmtExecutionScope() {
        if (stmt) {
            g_busyStatements.erase(stmt);
            if (ownsTempStmt) {
                sqlite3_finalize(stmt);
            } else {
                sqlite3_reset(stmt);
                sqlite3_clear_bindings(stmt);
            }
        }
    }

    StmtExecutionScope(const StmtExecutionScope&) = delete;
    StmtExecutionScope& operator=(const StmtExecutionScope&) = delete;
};

void logConfigSqliteError(const char* fmt, ...) {
    char buf[1024] = {};
    va_list args;
    va_start(args, fmt);
    std::vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    CCLog("%s", buf);
    gclient::diagnostics::CrashAndTelemetry::log(
        gclient::diagnostics::LogLevel::Error, "CConfigManager", "%s", buf);
}

std::string normalizeDbPath(const std::string& rawPath) {
    if (rawPath.empty()) return {};
    std::string out;
    out.reserve(rawPath.size());

    size_t startIdx = 0;
    if (rawPath.size() >= 2 &&
        (rawPath[0] == '/' || rawPath[0] == '\\') &&
        (rawPath[1] == '/' || rawPath[1] == '\\')) {
        out.append("//");
        startIdx = 2;
    }

    bool prevSlash = !out.empty();
    for (size_t i = startIdx; i < rawPath.size(); ++i) {
        const char c = (rawPath[i] == '\\') ? '/' : rawPath[i];
        if (c == '/') {
            if (!prevSlash) {
                out.push_back('/');
                prevSlash = true;
            }
        } else {
            out.push_back(c);
            prevSlash = false;
        }
    }

    while (out.size() >= 2 && out[0] == '.' && out[1] == '/') {
        out.erase(0, 2);
    }
    return out;
}

std::string quoteSqlIdentifier(const std::string& ident) {
    std::string out;
    out.reserve(ident.size() + 2);
    out.push_back('"');
    for (char c : ident) {
        if (c == '"') out += "\"\"";
        else out.push_back(c);
    }
    out.push_back('"');
    return out;
}

bool parseCanonicalInt64(const std::string& s, sqlite3_int64& outVal) {
    if (s.empty()) return false;
    if (s == "0") {
        outVal = 0;
        return true;
    }
    size_t idx = 0;
    if (s[0] == '-') {
        if (s.size() < 2 || s[1] < '1' || s[1] > '9') return false;
        idx = 1;
    } else if (s[0] < '1' || s[0] > '9') {
        return false;
    }
    for (size_t i = idx; i < s.size(); ++i) {
        if (s[i] < '0' || s[i] > '9') return false;
    }
    errno = 0;
    char* endPtr = nullptr;
    const long long parsed = std::strtoll(s.c_str(), &endPtr, 10);
    if (errno != 0 || endPtr != s.c_str() + s.size()) return false;
    outVal = static_cast<sqlite3_int64>(parsed);
    return true;
}

bool execPragma(sqlite3* db, const std::string& sql) {
    if (!db) return false;
    char* err = nullptr;
    const int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        logConfigSqliteError("CConfigManager PRAGMA failed (%s): %s", sql.c_str(), err ? err : "");
        if (err) sqlite3_free(err);
        return false;
    }
    return true;
}

bool isRegularFileUtf8(std::string_view utf8Path) {
    if (utf8Path.empty()) return false;
    std::error_code ec;
    return fs::is_regular_file(gclient::utf8::utf8ToFsPath(utf8Path), ec);
}

std::string copySqliteColumnBytes(sqlite3_stmt* stmt, int col) {
    if (!stmt) return {};
    const void* rawPtr = sqlite3_column_blob(stmt, col);
    const int byteCount = sqlite3_column_bytes(stmt, col);
    if (!rawPtr || byteCount <= 0) return {};
    // Re-fetch pointer after sqlite3_column_bytes per SQLite conversion rules.
    const char* safePtr = static_cast<const char*>(sqlite3_column_blob(stmt, col));
    return safePtr ? std::string(safePtr, static_cast<size_t>(byteCount)) : std::string{};
}

bool tryDecryptCell(std::vector<uint8_t>& buf, std::string& outPlain) {
    if (buf.empty()) return false;
    auto decSize = static_cast<unsigned long>(buf.size());
    if (!bt_decrypt(buf.data(), &decSize)) return false;
    const size_t safeLen = std::min<size_t>(static_cast<size_t>(decSize), buf.size());
    outPlain.assign(reinterpret_cast<const char*>(buf.data()), safeLen);
    return true;
}

} // namespace

// ============================================================================
// CTable
// ============================================================================

CTable::CTable(sqlite3* db, const std::string& dbPath, const std::string& tableName,
               const std::string& dbFile)
    : m_db(db), m_dbPath(dbPath), m_dbFile(dbFile), m_tableName(tableName) {}

CTable::CTable(sqlite3* db, const std::string& dbPath, const std::string& /*dbAlias*/,
               const std::string& tableName, bool /*needAttach*/)
    : m_db(db), m_dbPath(dbPath), m_tableName(tableName) {}

CTable::~CTable() {
    finalizeStatements();
}

void CTable::finalizeStatements() {
    std::lock_guard<std::recursive_mutex> lock(g_configSqliteMutex);
    if (m_stmtById) {
        g_busyStatements.erase(m_stmtById);
        sqlite3_finalize(m_stmtById);
        m_stmtById = nullptr;
    }
}

bool CTable::rebind(sqlite3* db, const std::string& dbPath) {
    std::lock_guard<std::recursive_mutex> lock(g_configSqliteMutex);
    finalizeStatements();
    m_db = db;
    m_dbPath = dbPath;
    return m_db ? init() : false;
}

std::string CTable::buildReadOnlyUri(const std::string& path) {
    std::string uri = "file:";
    uri.reserve(path.size() + 32);
    size_t startIdx = 0;
    if (path.size() >= 2 &&
        ((path[0] == '\\' && path[1] == '\\') || (path[0] == '/' && path[1] == '/'))) {
        uri += "//";
        startIdx = 2;
    } else if (path.size() >= 2 && path[1] == ':') {
        uri += "///";
    }
    for (size_t i = startIdx; i < path.size(); ++i) {
        const char c = path[i];
        if (c == '\\')      uri.push_back('/');
        else if (c == '%')  uri += "%25";
        else if (c == ' ')  uri += "%20";
        else if (c == '?')  uri += "%3F";
        else if (c == '#')  uri += "%23";
        else if (c == '\'') uri += "%27";
        else                uri.push_back(c);
    }
    uri += "?mode=ro";
    return uri;
}

bool CTable::init() {
    std::lock_guard<std::recursive_mutex> lock(g_configSqliteMutex);
    finalizeStatements();
    if (!m_db || m_tableName.empty()) return false;

    const std::string sql = "SELECT * FROM main." + quoteSqlIdentifier(m_tableName) + " WHERE id = ?1";
    if (sqlite3_prepare_v2(m_db, sql.c_str(), -1, &m_stmtById, nullptr) != SQLITE_OK) {
        logConfigSqliteError("sqlite3_prepare sql:%s db:%s failed:%s",
                             sql.c_str(), m_dbPath.c_str(), sqlite3_errmsg(m_db));
        m_stmtById = nullptr;
        return false;
    }
    return true;
}

CCArray* CTable::getRowById(const std::string& id) {
    std::lock_guard<std::recursive_mutex> lock(g_configSqliteMutex);
    if (!m_db || !m_stmtById) return nullptr;

    const std::string fallbackSql =
        "SELECT * FROM main." + quoteSqlIdentifier(m_tableName) + " WHERE id = ?1";
    StmtExecutionScope scope(m_db, m_stmtById, fallbackSql);
    sqlite3_stmt* activeStmt = scope.stmt;
    if (!activeStmt) return nullptr;

    if (sqlite3_bind_text(activeStmt, 1, id.c_str(), static_cast<int>(id.size()), SQLITE_TRANSIENT) != SQLITE_OK) {
        logConfigSqliteError("sqlite3_bind_text table:%s id:%s failed:%s",
                             m_tableName.c_str(), id.c_str(), sqlite3_errmsg(m_db));
        return nullptr;
    }

    int stepRc = sqlite3_step(activeStmt);
    if (stepRc == SQLITE_DONE) {
        sqlite3_int64 intId = 0;
        if (parseCanonicalInt64(id, intId)) {
            sqlite3_reset(activeStmt);
            sqlite3_clear_bindings(activeStmt);
            if (sqlite3_bind_int64(activeStmt, 1, intId) == SQLITE_OK) {
                stepRc = sqlite3_step(activeStmt);
            } else {
                logConfigSqliteError("sqlite3_bind_int64 table:%s id:%s failed:%s",
                                     m_tableName.c_str(), id.c_str(), sqlite3_errmsg(m_db));
            }
        }
    }

    if (stepRc != SQLITE_ROW) {
        if (stepRc != SQLITE_DONE) {
            logConfigSqliteError("sqlite3_step error table:%s id:%s rc:%d err:%s",
                                 m_tableName.c_str(), id.c_str(), stepRc, sqlite3_errmsg(m_db));
        } else {
            CCLog("sqlite3_step not found table:%s id:%s", m_tableName.c_str(), id.c_str());
        }
        return nullptr;
    }

    // Copy all column blobs out of SQLite's active row page buffer before invoking bt_decrypt.
    const int colCount = sqlite3_data_count(activeStmt);
    std::vector<std::string> copiedCols(static_cast<size_t>((std::max)(0, colCount)));
    for (int col = 0; col < colCount; ++col) {
        copiedCols[static_cast<size_t>(col)] = copySqliteColumnBytes(activeStmt, col);
    }

    CCArray* arr = CCArray::create();
    if (!arr) return nullptr;

    CCFileUtils* fu = ax::FileUtils::getInstance();
    for (int col = 0; col < colCount; ++col) {
        const std::string& rawCol = copiedCols[static_cast<size_t>(col)];
        if (rawCol.empty()) {
            arr->addObject(CCString::create(""));
            continue;
        }

        if (col == colCount - 1 && fu != nullptr) {
            size_t trimmedLen = rawCol.size();
            while (trimmedLen > 0 &&
                   (rawCol[trimmedLen - 1] == '\r' || rawCol[trimmedLen - 1] == '\n' ||
                    rawCol[trimmedLen - 1] == ' '  || rawCol[trimmedLen - 1] == '\t')) {
                --trimmedLen;
            }
            std::vector<uint8_t> workBuf;
            std::string plain;
            if (trimmedLen >= 2 &&
                gclient::crypto::hexDecode(std::string_view(rawCol.data(), trimmedLen), workBuf) &&
                tryDecryptCell(workBuf, plain)) {
                arr->addObject(CCString::create(plain));
                continue;
            }
            if (rawCol.size() > 8 &&
                gclient::common::readLE<uint32_t>(reinterpret_cast<const uint8_t*>(rawCol.data())) ==
                    gclient::assets::kBtDecryptMagic) {
                workBuf.assign(rawCol.begin(), rawCol.end());
                if (tryDecryptCell(workBuf, plain)) {
                    arr->addObject(CCString::create(plain));
                    continue;
                }
            }
        }

        arr->addObject(CCString::create(rawCol));
    }
    return arr;
}

CCArray* CTable::getColName() {
    std::lock_guard<std::recursive_mutex> lock(g_configSqliteMutex);
    CCArray* arr = CCArray::create();
    if (!arr || !m_db || m_tableName.empty()) return arr;

    const std::string sql = "SELECT * FROM main." + quoteSqlIdentifier(m_tableName) + " LIMIT 1";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(m_db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK || !stmt) {
        logConfigSqliteError("sqlite3_prepare sql:%s db:%s failed:%s",
                             sql.c_str(), m_dbPath.c_str(), sqlite3_errmsg(m_db));
        return arr;
    }
    StmtFinalizeGuard stmtGuard(stmt);

    const int stepRc = sqlite3_step(stmt);
    if (stepRc != SQLITE_ROW && stepRc != SQLITE_DONE) {
        logConfigSqliteError("sqlite3_step getColName sql:%s rc:%d err:%s",
                             sql.c_str(), stepRc, sqlite3_errmsg(m_db));
    }
    const int colCount = (stepRc == SQLITE_ROW) ? sqlite3_data_count(stmt) : sqlite3_column_count(stmt);
    for (int i = 0; i < colCount; ++i) {
        const char* name = sqlite3_column_name(stmt, i);
        arr->addObject(CCString::create(name ? name : ""));
    }
    return arr;
}

CCArray* CTable::getIdsByConditionStr(const std::string& condition) {
    std::lock_guard<std::recursive_mutex> lock(g_configSqliteMutex);
    CCArray* arr = CCArray::create();
    if (!arr || !m_db || m_tableName.empty() || gclient::common::trimAscii(condition).empty()) {
        return arr;
    }

    const std::string sql =
        "SELECT id FROM main." + quoteSqlIdentifier(m_tableName) + " WHERE " + condition;
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(m_db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK || !stmt) {
        logConfigSqliteError("sqlite3_prepare sql:%s db:%s failed:%s",
                             sql.c_str(), m_dbPath.c_str(), sqlite3_errmsg(m_db));
        return arr;
    }
    StmtFinalizeGuard stmtGuard(stmt);

    int stepRc = SQLITE_OK;
    while ((stepRc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const int colCount = sqlite3_data_count(stmt);
        for (int i = 0; i < colCount; ++i) {
            arr->addObject(CCString::create(copySqliteColumnBytes(stmt, i)));
        }
    }
    if (stepRc != SQLITE_DONE) {
        logConfigSqliteError("sqlite3_step condition sql:%s rc:%d err:%s",
                             sql.c_str(), stepRc, sqlite3_errmsg(m_db));
    }
    return arr;
}

// ============================================================================
// CConfigurationManager
// ============================================================================

static CConfigurationManager* s_configMgr = nullptr;

CConfigurationManager* CConfigurationManager::sharedConfigurationManager(bool reloadFlag) {
    std::lock_guard<std::recursive_mutex> lock(g_configSqliteMutex);
    if (!s_configMgr) {
        s_configMgr = new CConfigurationManager();
        if (!s_configMgr->init()) {
            delete s_configMgr;
            s_configMgr = nullptr;
        }
        return s_configMgr;
    }
    if (reloadFlag) s_configMgr->reload();
    return s_configMgr;
}

CConfigurationManager::CConfigurationManager() = default;

CConfigurationManager::~CConfigurationManager() {
    std::lock_guard<std::recursive_mutex> lock(g_configSqliteMutex);
    for (CTable* tbl : m_ownedTables) {
        if (tbl) {
            tbl->finalizeStatements();
            delete tbl;
        }
    }
    m_ownedTables.clear();
    m_tables.clear();
    closeAllDbs();
}

bool CConfigurationManager::init() { return true; }

void CConfigurationManager::closeAllDbs() {
    std::lock_guard<std::recursive_mutex> lock(g_configSqliteMutex);
    for (CTable* tbl : m_ownedTables) {
        if (tbl) tbl->finalizeStatements();
    }
    for (auto& [path, db] : m_dbs) {
        if (db) {
            while (sqlite3_stmt* leftover = sqlite3_next_stmt(db, nullptr)) {
                g_busyStatements.erase(leftover);
                sqlite3_finalize(leftover);
            }
            const int rc = sqlite3_close(db);
            if (rc != SQLITE_OK) {
                logConfigSqliteError("sqlite3_close busy for '%s' (rc=%d), falling back to sqlite3_close_v2",
                                     path.c_str(), rc);
                sqlite3_close_v2(db);
            }
        }
    }
    m_dbs.clear();
}

bool CConfigurationManager::reload() {
    std::lock_guard<std::recursive_mutex> lock(g_configSqliteMutex);
    closeAllDbs();
    m_tables.clear();

    bool allOk = true;
    for (CTable* tbl : m_ownedTables) {
        if (!tbl) continue;
        std::string refreshedPath = tbl->dbFile().empty()
            ? std::string{}
            : normalizeDbPath(getDbFile(tbl->dbFile()));
        if (refreshedPath.empty()) refreshedPath = tbl->dbPath();
        if (!tbl->rebind(openOrGetDb(refreshedPath), refreshedPath)) {
            allOk = false;
        }
        m_tables[refreshedPath + ":" + tbl->tableName()] = tbl;
    }
    return allOk;
}

sqlite3* CConfigurationManager::openOrGetDb(const std::string& normalizedPath) {
    if (normalizedPath.empty()) return nullptr;
    if (auto it = m_dbs.find(normalizedPath); it != m_dbs.end() && it->second != nullptr) {
        return it->second;
    }

    sqlite3* db = nullptr;
    const std::string readOnlyUri = CTable::buildReadOnlyUri(normalizedPath);
    if (sqlite3_open_v2(readOnlyUri.c_str(), &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nullptr) != SQLITE_OK) {
        logConfigSqliteError("CConfigManager sqlite3_open_v2 failed for '%s': %s",
                             normalizedPath.c_str(), db ? sqlite3_errmsg(db) : "out of memory");
        if (db) sqlite3_close(db);
        return nullptr;
    }

#ifdef SQLITE_DBCONFIG_DQS_DML
    sqlite3_db_config(db, SQLITE_DBCONFIG_DQS_DML, 1, nullptr);
#endif
#ifdef SQLITE_DBCONFIG_DQS_DDL
    sqlite3_db_config(db, SQLITE_DBCONFIG_DQS_DDL, 1, nullptr);
#endif

    char pragmaBuf[128];
    std::snprintf(pragmaBuf, sizeof(pragmaBuf), "PRAGMA cache_size = %d;", kAttachedCacheSizeKiB);
    execPragma(db, pragmaBuf);
    execPragma(db, "PRAGMA temp_store = MEMORY;");
    execPragma(db, "PRAGMA query_only = ON;");

    m_dbs[normalizedPath] = db;
    return db;
}

std::string CConfigurationManager::getDbFile(const std::string& dbFile) {
    if (dbFile.empty()) return {};
    CCFileUtils* fu = ax::FileUtils::getInstance();
    if (!fu) return {};

    const std::string candidates[] = {dbFile, "database/" + dbFile, "res/database/" + dbFile};
    for (const std::string& cand : candidates) {
        const std::string full = fu->fullPathForFilename(cand);
        if (!full.empty() && isRegularFileUtf8(full)) return full;
    }
    return {};
}

CTable* CConfigurationManager::getTable(const std::string& dbFile, const std::string& tableName) {
    std::lock_guard<std::recursive_mutex> lock(g_configSqliteMutex);
    if (dbFile.empty() || tableName.empty()) return nullptr;

    const std::string rawResolved = getDbFile(dbFile);
    if (rawResolved.empty()) {
        logConfigSqliteError("CConfigManager::getTable could not find dbFile '%s' (table '%s')",
                             dbFile.c_str(), tableName.c_str());
        return nullptr;
    }

    const std::string resolvedPath = normalizeDbPath(rawResolved);
    const std::string cacheKey = resolvedPath + ":" + tableName;
    if (auto it = m_tables.find(cacheKey); it != m_tables.end()) {
        return it->second;
    }

    sqlite3* db = openOrGetDb(resolvedPath);
    if (!db) return nullptr;

    auto* table = new CTable(db, resolvedPath, tableName, dbFile);
    if (!table->init()) {
        delete table;
        return nullptr;
    }

    m_ownedTables.push_back(table);
    m_tables[cacheKey] = table;
    return table;
}
