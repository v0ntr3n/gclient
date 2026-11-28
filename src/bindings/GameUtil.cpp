#include "GameUtil.h"
#include "common/KestrelBinaryReader.h"
#include "common/KestrelCrypto.h"
#include "common/KestrelUtf8.h"

#if defined(__has_include)
#  if __has_include("net/LCPacket.h")
#    include "net/LCPacket.h"
#  elif __has_include("../net/LCPacket.h")
#    include "../net/LCPacket.h"
#  else
#    include "net/LCPacket.h"
#  endif
#else
#  include "net/LCPacket.h"
#endif

#include "support/zip_support/unzip.h"
#include <zlib.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <span>
#include <string_view>
#include <vector>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <Windows.h>
#  include <direct.h>
#  include <io.h>
#else
#  include <unistd.h>
#endif

USING_NS_CC;
namespace fs = std::filesystem;

namespace {

using gclient::common::readBE;
using gclient::common::readLE;
using gclient::common::writeBE;
using gclient::utf8::fsPathToUtf8;
using gclient::utf8::utf8ToFsPath;

fs::path cstrToPath(const char* utf8) {
    return (utf8 && *utf8) ? utf8ToFsPath(utf8) : fs::path{};
}

FILE* openFileRb(const fs::path& p) {
    if (p.empty()) return nullptr;
#ifdef _WIN32
    return ::_wfopen(p.c_str(), L"rb");
#else
    return std::fopen(p.c_str(), "rb");
#endif
}

FILE* openFileWb(const fs::path& p) {
    if (p.empty()) return nullptr;
#ifdef _WIN32
    return ::_wfopen(p.c_str(), L"wb");
#else
    return std::fopen(p.c_str(), "wb");
#endif
}

bool normalizeZipEntryRelativePath(const char* rawEntryName, fs::path& outRel, bool& outIsDir) {
    outRel.clear();
    outIsDir = false;
    if (!rawEntryName || !*rawEntryName) return false;

    std::string normalized(rawEntryName);
    std::replace(normalized.begin(), normalized.end(), '\\', '/');
    if (!normalized.empty() && normalized.back() == '/') {
        outIsDir = true;
    }
    while (!normalized.empty() && normalized.front() == '/') {
        normalized.erase(normalized.begin());
    }
    while (!normalized.empty() && normalized.back() == '/') {
        normalized.pop_back();
    }
    if (normalized.empty()) {
        return outIsDir;
    }

    const fs::path candidate = utf8ToFsPath(normalized);
    if (candidate.empty() || candidate.is_absolute() || candidate.has_root_name()) {
        return false;
    }
    for (const fs::path& part : candidate) {
        if (part == "..") return false;
    }
    outRel = candidate;
    return true;
}

// Unicode-safe Central Directory ZIP extractor used when unzOpen cannot open UTF-8 paths on Win32.
int extractZipViaFileStream(FILE* zfp, const fs::path& baseDir) {
    if (std::fseek(zfp, 0, SEEK_END) != 0) return GameUtil::EUnzipBadFile;
    const long fileLenLong = std::ftell(zfp);
    if (fileLenLong < 22) return GameUtil::EUnzipBadFile;

    const auto fileLen = static_cast<size_t>(fileLenLong);
    const size_t tailLen = std::min<size_t>(fileLen, 65557u);
    std::vector<uint8_t> tail(tailLen);
    if (std::fseek(zfp, static_cast<long>(fileLen - tailLen), SEEK_SET) != 0 ||
        std::fread(tail.data(), 1, tailLen, zfp) != tailLen) {
        return GameUtil::EUnzipBadFile;
    }

    size_t eocdPos = tailLen;
    for (size_t i = tailLen - 22; ; --i) {
        if (readLE<uint32_t>(tail.data() + i) == 0x06054b50u) {
            eocdPos = i;
            break;
        }
        if (i == 0) break;
    }
    if (eocdPos == tailLen) return GameUtil::EUnzipBadFile;

    const uint8_t* eocd = tail.data() + eocdPos;
    const auto totalEntries = readLE<uint16_t>(eocd + 10);
    const auto cdSize = readLE<uint32_t>(eocd + 12);
    const auto cdOffset = readLE<uint32_t>(eocd + 16);
    if (static_cast<size_t>(cdOffset) > fileLen ||
        static_cast<size_t>(cdSize) > fileLen - static_cast<size_t>(cdOffset)) {
        return GameUtil::EUnzipBadFile;
    }

    std::vector<uint8_t> cd(cdSize);
    if (cdSize > 0 &&
        (std::fseek(zfp, static_cast<long>(cdOffset), SEEK_SET) != 0 ||
         std::fread(cd.data(), 1, cdSize, zfp) != cdSize)) {
        return GameUtil::EUnzipBadFile;
    }

    size_t cdCursor = 0;
    uint8_t inBuf[16384];
    uint8_t outBuf[16384];

    for (uint16_t idx = 0; idx < totalEntries; ++idx) {
        if (cdCursor + 46 > cd.size()) return GameUtil::EUnzipBadFile;
        const uint8_t* entry = cd.data() + cdCursor;
        if (readLE<uint32_t>(entry) != 0x02014b50u) return GameUtil::EUnzipBadFile;

        const auto method = readLE<uint16_t>(entry + 10);
        const auto compSize = readLE<uint32_t>(entry + 20);
        const auto nameLen = readLE<uint16_t>(entry + 28);
        const auto extraLen = readLE<uint16_t>(entry + 30);
        const auto commentLen = readLE<uint16_t>(entry + 32);
        const auto localHeaderOff = readLE<uint32_t>(entry + 42);

        const size_t varMetaLen =
            static_cast<size_t>(nameLen) + static_cast<size_t>(extraLen) + static_cast<size_t>(commentLen);
        if (cd.size() - cdCursor < 46u || (cd.size() - cdCursor - 46u) < varMetaLen) {
            return GameUtil::EUnzipBadFile;
        }
        std::string entryName(reinterpret_cast<const char*>(entry + 46), nameLen);
        cdCursor += 46 + varMetaLen;

        fs::path relPath;
        bool isDir = false;
        if (!normalizeZipEntryRelativePath(entryName.c_str(), relPath, isDir)) {
            return GameUtil::EUnzipBadFile;
        }
        const fs::path targetPath = baseDir.empty() ? relPath : (baseDir / relPath);
        if (targetPath.empty()) continue;

        if (isDir) {
            std::error_code ec;
            if (!fs::is_directory(targetPath, ec) && !fs::create_directories(targetPath, ec)) {
                return GameUtil::EUnzipOutOfStorage;
            }
            continue;
        }

        if (static_cast<size_t>(localHeaderOff) > fileLen ||
            fileLen - static_cast<size_t>(localHeaderOff) < 30u) {
            return GameUtil::EUnzipBadFile;
        }
        uint8_t localHdr[30];
        if (std::fseek(zfp, static_cast<long>(localHeaderOff), SEEK_SET) != 0 ||
            std::fread(localHdr, 1, sizeof(localHdr), zfp) != sizeof(localHdr) ||
            readLE<uint32_t>(localHdr) != 0x04034b50u) {
            return GameUtil::EUnzipBadFile;
        }
        const size_t localHdrTotal =
            30u + static_cast<size_t>(readLE<uint16_t>(localHdr + 26)) +
            static_cast<size_t>(readLE<uint16_t>(localHdr + 28));
        if (fileLen - static_cast<size_t>(localHeaderOff) < localHdrTotal) {
            return GameUtil::EUnzipBadFile;
        }
        const size_t dataOffset = static_cast<size_t>(localHeaderOff) + localHdrTotal;
        if (static_cast<size_t>(compSize) > fileLen - dataOffset ||
            std::fseek(zfp, static_cast<long>(dataOffset), SEEK_SET) != 0) {
            return GameUtil::EUnzipBadFile;
        }

        std::error_code ec;
        if (const fs::path parent = targetPath.parent_path(); !parent.empty()) {
            fs::create_directories(parent, ec);
        }
        FILE* fp = openFileWb(targetPath);
        if (!fp) return GameUtil::EUnzipBadFile;

        if (method == 0) {
            size_t rem = compSize;
            while (rem > 0) {
                const size_t chunk = std::min<size_t>(rem, sizeof(inBuf));
                if (std::fread(inBuf, 1, chunk, zfp) != chunk) {
                    std::fclose(fp);
                    return GameUtil::EUnzipBadFile;
                }
                if (std::fwrite(inBuf, 1, chunk, fp) != chunk) {
                    std::fclose(fp);
                    return GameUtil::EUnzipOutOfStorage;
                }
                rem -= chunk;
            }
        } else if (method == 8) {
            z_stream strm{};
            if (inflateInit2(&strm, -MAX_WBITS) != Z_OK) {
                std::fclose(fp);
                return GameUtil::EUnzipBadFile;
            }
            size_t rem = compSize;
            int zrc = Z_OK;
            while (rem > 0 && zrc != Z_STREAM_END) {
                const size_t chunk = std::min<size_t>(rem, sizeof(inBuf));
                if (std::fread(inBuf, 1, chunk, zfp) != chunk) {
                    inflateEnd(&strm);
                    std::fclose(fp);
                    return GameUtil::EUnzipBadFile;
                }
                rem -= chunk;
                strm.next_in = inBuf;
                strm.avail_in = static_cast<uInt>(chunk);
                do {
                    strm.next_out = outBuf;
                    strm.avail_out = sizeof(outBuf);
                    zrc = inflate(&strm, Z_NO_FLUSH);
                    if (zrc != Z_OK && zrc != Z_STREAM_END) {
                        inflateEnd(&strm);
                        std::fclose(fp);
                        return GameUtil::EUnzipBadFile;
                    }
                    const size_t produced = sizeof(outBuf) - strm.avail_out;
                    if (produced > 0 && std::fwrite(outBuf, 1, produced, fp) != produced) {
                        inflateEnd(&strm);
                        std::fclose(fp);
                        return GameUtil::EUnzipOutOfStorage;
                    }
                } while (strm.avail_out == 0);
            }
            inflateEnd(&strm);
            if (zrc != Z_STREAM_END && compSize > 0) {
                std::fclose(fp);
                return GameUtil::EUnzipBadFile;
            }
        } else {
            std::fclose(fp);
            return GameUtil::EUnzipBadFile;
        }
        std::fclose(fp);
    }

    return GameUtil::EUnzipOk;
}

} // namespace

int GameUtil::rename(const char* oldPath, const char* newPath) {
    if (!oldPath || !newPath) return -1;
#ifdef _WIN32
    const std::wstring oldW = gclient::utf8::utf8ToWide(oldPath);
    const std::wstring newW = gclient::utf8::utf8ToWide(newPath);
    if (oldW.empty() || newW.empty()) return -1;
    std::error_code ec;
    if (const fs::path parent = fs::path(newW).parent_path(); !parent.empty()) {
        fs::create_directories(parent, ec);
    }
    return ::MoveFileExW(oldW.c_str(), newW.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED) ? 0 : -1;
#else
    std::error_code ec;
    if (const fs::path parent = fs::path(newPath).parent_path(); !parent.empty()) {
        fs::create_directories(parent, ec);
    }
    return std::rename(oldPath, newPath);
#endif
}

int GameUtil::mkdir(const char* path) {
    const fs::path p = cstrToPath(path);
    if (p.empty()) return -1;
    std::error_code ec;
    if (fs::is_directory(p, ec)) return 0;
    ec.clear();
    return (fs::create_directories(p, ec) || fs::is_directory(p, ec)) ? 0 : -1;
}

int GameUtil::rmdir(const char* path) {
    const fs::path p = cstrToPath(path);
    if (p.empty()) return -1;
    std::error_code ec;
    return fs::remove(p, ec) ? 0 : -1;
}

int GameUtil::unlink(const char* path) {
    if (!path || !*path) return -1;
#ifdef _WIN32
    const std::wstring w = gclient::utf8::utf8ToWide(path);
    return w.empty() ? -1 : ::_wunlink(w.c_str());
#else
    return ::unlink(path);
#endif
}

int GameUtil::access(const char* path, int mode) {
    if (!path || !*path) return -1;
#ifdef _WIN32
    const std::wstring w = gclient::utf8::utf8ToWide(path);
    // MSVC _waccess only supports 00, 02, 04, and 06; mask bit 1 to avoid assertions on EXOk.
    return w.empty() ? -1 : ::_waccess(w.c_str(), mode & 0x06);
#else
    return ::access(path, mode);
#endif
}

bool GameUtil::isDir(const char* path) {
    const fs::path p = cstrToPath(path);
    if (p.empty()) return false;
    std::error_code ec;
    return fs::is_directory(p, ec);
}

CCArray* GameUtil::readdir(const char* path) {
    CCArray* arr = CCArray::create();
    const fs::path p = cstrToPath(path);
    if (p.empty()) return arr;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(p, ec)) {
        arr->addObject(CCString::create(fsPathToUtf8(entry.path().filename())));
    }
    return arr;
}

int GameUtil::getDPI() {
    return 160;
}

std::string GameUtil::getExternalStorageLocation() {
    return ax::FileUtils::getInstance()->getWritablePath();
}

int GameUtil::unzip(const char* zipPath, const char* dstDir) {
    const fs::path zipFsPath = cstrToPath(zipPath);
    if (zipFsPath.empty()) return EUnzipFileNotExist;
    std::error_code existEc;
    if (!fs::exists(zipFsPath, existEc) || fs::is_directory(zipFsPath, existEc)) {
        return EUnzipFileNotExist;
    }

    const fs::path baseDir = cstrToPath(dstDir);
    unzFile zf = nullptr;
#ifdef _WIN32
    bool isPureAscii = true;
    for (const auto* p = reinterpret_cast<const unsigned char*>(zipPath); *p != '\0'; ++p) {
        if (*p >= 0x80u) {
            isPureAscii = false;
            break;
        }
    }
    if (isPureAscii) zf = unzOpen(zipPath);
#else
    zf = unzOpen(zipPath);
#endif

    if (!zf) {
        FILE* zfp = openFileRb(zipFsPath);
        if (!zfp) return EUnzipFileNotExist;
        const int streamRes = extractZipViaFileStream(zfp, baseDir);
        std::fclose(zfp);
        return streamRes;
    }

    unz_global_info gi{};
    if (unzGetGlobalInfo(zf, &gi) != UNZ_OK) {
        unzClose(zf);
        return EUnzipBadFile;
    }

    char readBuf[4096];
    for (uLong i = 0; i < gi.number_entry; ++i) {
        unz_file_info fi{};
        if (unzGetCurrentFileInfo(zf, &fi, nullptr, 0, nullptr, 0, nullptr, 0) != UNZ_OK ||
            fi.size_filename > 4096u) {
            unzClose(zf);
            return EUnzipBadFile;
        }
        std::string dynName(static_cast<size_t>(fi.size_filename) + 1u, '\0');
        if (unzGetCurrentFileInfo(zf, &fi, dynName.data(), static_cast<uLong>(dynName.size()),
                                  nullptr, 0, nullptr, 0) != UNZ_OK) {
            unzClose(zf);
            return EUnzipBadFile;
        }

        fs::path relPath;
        bool isDirEntry = false;
        if (!normalizeZipEntryRelativePath(dynName.c_str(), relPath, isDirEntry)) {
            unzClose(zf);
            return EUnzipBadFile;
        }
        const fs::path targetPath = baseDir.empty() ? relPath : (baseDir / relPath);

        if (isDirEntry) {
            if (!targetPath.empty()) {
                std::error_code ec;
                if (!fs::is_directory(targetPath, ec) && !fs::create_directories(targetPath, ec)) {
                    unzClose(zf);
                    return EUnzipOutOfStorage;
                }
            }
        } else if (!targetPath.empty()) {
            if (unzOpenCurrentFile(zf) != UNZ_OK) {
                unzClose(zf);
                return EUnzipBadFile;
            }
            std::error_code ec;
            if (const fs::path parent = targetPath.parent_path(); !parent.empty()) {
                fs::create_directories(parent, ec);
            }
            FILE* fp = openFileWb(targetPath);
            if (!fp) {
                unzCloseCurrentFile(zf);
                unzClose(zf);
                return EUnzipBadFile;
            }
            int n = 0;
            bool writeFailed = false;
            while ((n = unzReadCurrentFile(zf, readBuf, sizeof(readBuf))) > 0) {
                if (std::fwrite(readBuf, 1, static_cast<size_t>(n), fp) != static_cast<size_t>(n)) {
                    writeFailed = true;
                    break;
                }
            }
            std::fclose(fp);
            unzCloseCurrentFile(zf);
            if (writeFailed) {
                unzClose(zf);
                return EUnzipOutOfStorage;
            }
            if (n < 0) {
                unzClose(zf);
                return EUnzipBadFile;
            }
        }
        if (i + 1 < gi.number_entry && unzGoToNextFile(zf) != UNZ_OK) {
            unzClose(zf);
            return EUnzipBadFile;
        }
    }
    unzClose(zf);
    return EUnzipOk;
}

std::string GameUtil::convertEncoding(const char* str, const char* /*encoding*/) {
    return str ? std::string(str) : "";
}

CCArray* GameUtil::getAssetFiles(const char* subDir) {
    const std::string base = ax::FileUtils::getInstance()->fullPathForFilename(subDir ? subDir : "");
    return readdir(base.c_str());
}

bool GameUtil::checkRecordPermission() { return false; }
void GameUtil::installApk(const char* /*path*/) {}
void GameUtil::setTimeZone(int /*tz*/) {}

uint64_t GameUtil::getMicroSeconds() {
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(now).count());
}

std::string GameUtil::makeLCPacket(const std::string& data) {
    return gclient::net::LCPacket::makeLCPacket(data, true);
}

uint32_t GameUtil::getU32(const std::string& data) {
    return readBE<uint32_t>(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(data.data()), data.size()));
}

std::string GameUtil::writeU32(uint32_t val, char* optionalBuf) {
    std::string out(4, '\0');
    writeBE<uint32_t>(reinterpret_cast<uint8_t*>(out.data()), val);
    if (optionalBuf) {
        std::memcpy(optionalBuf, out.data(), 4);
    }
    return out;
}

std::string GameUtil::zipData(const std::string& data) {
    if (data.empty()) return "";
    std::string out;
    return gclient::crypto::zlibCompress(data.data(), data.size(), out) ? out : std::string{};
}

std::string GameUtil::unzipData(const std::string& data) {
    if (data.empty()) return "";
    std::string out;
    if (gclient::crypto::zlibDecompress(data.data(), data.size(), out) ||
        gclient::net::LCPacket::zlibDecompress(
            reinterpret_cast<const uint8_t*>(data.data()), data.size(), out)) {
        return out;
    }
    return "";
}

std::string GameUtil::urlEncode(const std::string& str) {
    return gclient::utf8::urlEncode(str);
}

std::string GameUtil::urlDecode(const std::string& str) {
    return gclient::utf8::urlDecode(str);
}
