#include "Amf3Module.h"
#include "net/Amf3WireCodec.h"

extern "C" {
#include "lauxlib.h"
#include "lua.h"
}

#include <cmath>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

using gclient::amf3::appendDoubleBE;
using gclient::amf3::appendU29;
using gclient::amf3::kIntMax;
using gclient::amf3::kIntMin;
using gclient::amf3::kMarkerArray;
using gclient::amf3::kMarkerByteArray;
using gclient::amf3::kMarkerDate;
using gclient::amf3::kMarkerDouble;
using gclient::amf3::kMarkerFalse;
using gclient::amf3::kMarkerInteger;
using gclient::amf3::kMarkerNull;
using gclient::amf3::kMarkerObject;
using gclient::amf3::kMarkerString;
using gclient::amf3::kMarkerTrue;
using gclient::amf3::kMarkerUndefined;
using gclient::amf3::kMarkerXml;
using gclient::amf3::kMarkerXmlDoc;
using gclient::amf3::kMaxRecursionDepth;
using gclient::amf3::readDoubleBEChecked;
using gclient::amf3::readU29Checked;

inline size_t luaRawLength(lua_State* L, int idx) {
#if LUA_VERSION_NUM == 501
    return lua_objlen(L, idx);
#else
    return lua_rawlen(L, idx);
#endif
}

inline int toAbsIndex(lua_State* L, int idx) {
    return (idx > 0 || idx <= LUA_REGISTRYINDEX) ? idx : (lua_gettop(L) + idx + 1);
}

inline bool isDenseArrayIndex(double kd, size_t denseCount) noexcept {
    return std::isfinite(kd) && kd >= 1.0 && kd <= static_cast<double>(denseCount) && std::floor(kd) == kd;
}

struct Amf3ErrorState {
    char buf[256] = {};
    bool hasError = false;

    void set(const char* fmt, ...) {
        if (hasError) return;
        hasError = true;
        va_list args;
        va_start(args, fmt);
        std::vsnprintf(buf, sizeof(buf), fmt, args);
        va_end(args);
    }
};

struct ObjectRefEntry {
    uint32_t refIdx = 0;
    uint8_t marker = kMarkerObject;
};

struct LuaAmf3Encoder {
    lua_State* L = nullptr;
    std::string out;
    std::unordered_map<std::string, uint32_t> stringRefs;
    std::unordered_map<const void*, ObjectRefEntry> objectRefs;
    Amf3ErrorState err;

    void writeByte(uint8_t b) { out.push_back(static_cast<char>(b)); }

    bool writeUtf8Vr(const char* str, size_t len) {
        if (len == 0) {
            writeByte(0x01u);
            return true;
        }
        std::string key(str, len);
        auto it = stringRefs.find(key);
        if (it != stringRefs.end()) {
            appendU29(out, it->second << 1);
            return true;
        }
        if (len > static_cast<size_t>(kIntMax)) {
            err.set("amf3.encode: string length exceeds U29 limit");
            return false;
        }
        const uint32_t refIdx = static_cast<uint32_t>(stringRefs.size());
        if (refIdx <= static_cast<uint32_t>(kIntMax)) {
            stringRefs.emplace(std::move(key), refIdx);
        }
        appendU29(out, (static_cast<uint32_t>(len) << 1) | 1u);
        out.append(str, len);
        return true;
    }

    void encodeNumber(double d) {
        if (std::isfinite(d) && d >= static_cast<double>(kIntMin) && d <= static_cast<double>(kIntMax)) {
            const int32_t iv = static_cast<int32_t>(d);
            if (static_cast<double>(iv) == d && !(d == 0.0 && std::signbit(d))) {
                writeByte(kMarkerInteger);
                appendU29(out, static_cast<uint32_t>(iv) & 0x1FFFFFFFu);
                return;
            }
        }
        writeByte(kMarkerDouble);
        appendDoubleBE(out, d);
    }

    // Serializes the key-value pair currently at (key = -2, val = -1) without mutating numeric keys.
    bool encodeAssocPairAtTop(int depth) {
        const int keyType = lua_type(L, -2);
        if (keyType == LUA_TSTRING) {
            size_t klen = 0;
            const char* kstr = lua_tolstring(L, -2, &klen);
            if (klen > 0 && (!writeUtf8Vr(kstr, klen) || !encodeValue(-1, depth + 1))) {
                return false;
            }
        } else if (keyType == LUA_TNUMBER) {
            lua_pushvalue(L, -2);
            size_t klen = 0;
            const char* kstr = lua_tolstring(L, -1, &klen);
            const bool ok = (kstr == nullptr || klen == 0) ||
                            (writeUtf8Vr(kstr, klen) && encodeValue(-2, depth + 1));
            lua_pop(L, 1);
            if (!ok) return false;
        }
        return true;
    }

    bool encodeTable(int idx, int depth) {
        if (depth > kMaxRecursionDepth) {
            err.set("amf3.encode: maximum nesting depth exceeded");
            return false;
        }
        if (!lua_checkstack(L, 8)) {
            err.set("amf3: Lua stack overflow");
            return false;
        }

        const int absIdx = toAbsIndex(L, idx);
        const void* ptr = lua_topointer(L, absIdx);
        if (ptr != nullptr) {
            auto refIt = objectRefs.find(ptr);
            if (refIt != objectRefs.end()) {
                writeByte(refIt->second.marker);
                appendU29(out, refIt->second.refIdx << 1);
                return true;
            }
        }

        const size_t rawLen = luaRawLength(L, absIdx);
        size_t denseCount = 0;
        for (size_t i = 1; i <= rawLen; ++i) {
            lua_rawgeti(L, absIdx, static_cast<int>(i));
            const bool isNil = lua_isnil(L, -1) != 0;
            lua_pop(L, 1);
            if (isNil) break;
            denseCount = i;
        }

        bool hasNonDenseKeys = false;
        lua_pushnil(L);
        while (lua_next(L, absIdx) != 0) {
            if (lua_type(L, -2) != LUA_TNUMBER || !isDenseArrayIndex(lua_tonumber(L, -2), denseCount)) {
                hasNonDenseKeys = true;
            }
            lua_pop(L, 1);
        }

        const bool encodeAsObject = (denseCount == 0 && hasNonDenseKeys);
        const uint8_t tableMarker = encodeAsObject ? kMarkerObject : kMarkerArray;
        if (ptr != nullptr) {
            objectRefs.emplace(ptr, ObjectRefEntry{static_cast<uint32_t>(objectRefs.size()), tableMarker});
        }

        if (encodeAsObject) {
            writeByte(kMarkerObject);
            appendU29(out, 0x0Bu);
            writeByte(0x01u);
            lua_pushnil(L);
            while (lua_next(L, absIdx) != 0) {
                if (!lua_checkstack(L, 8)) {
                    lua_pop(L, 2);
                    err.set("amf3: Lua stack overflow");
                    return false;
                }
                if (!encodeAssocPairAtTop(depth)) {
                    lua_pop(L, 2);
                    return false;
                }
                lua_pop(L, 1);
            }
            writeByte(0x01u);
            return true;
        }

        writeByte(kMarkerArray);
        appendU29(out, (static_cast<uint32_t>(denseCount) << 1) | 1u);
        if (hasNonDenseKeys) {
            lua_pushnil(L);
            while (lua_next(L, absIdx) != 0) {
                if (!lua_checkstack(L, 8)) {
                    lua_pop(L, 2);
                    err.set("amf3: Lua stack overflow");
                    return false;
                }
                const bool skipDense = (lua_type(L, -2) == LUA_TNUMBER) &&
                                       isDenseArrayIndex(lua_tonumber(L, -2), denseCount);
                if (!skipDense && !encodeAssocPairAtTop(depth)) {
                    lua_pop(L, 2);
                    return false;
                }
                lua_pop(L, 1);
            }
        }
        writeByte(0x01u);

        for (size_t i = 1; i <= denseCount; ++i) {
            if (!lua_checkstack(L, 8)) {
                err.set("amf3: Lua stack overflow");
                return false;
            }
            lua_rawgeti(L, absIdx, static_cast<int>(i));
            const bool ok = encodeValue(-1, depth + 1);
            lua_pop(L, 1);
            if (!ok) return false;
        }
        return true;
    }

    bool encodeValue(int idx, int depth) {
        if (!lua_checkstack(L, 8)) {
            err.set("amf3: Lua stack overflow");
            return false;
        }
        const int type = lua_type(L, idx);
        switch (type) {
            case LUA_TNIL:
            case LUA_TLIGHTUSERDATA:
                writeByte(kMarkerNull);
                return true;
            case LUA_TBOOLEAN:
                writeByte(lua_toboolean(L, idx) ? kMarkerTrue : kMarkerFalse);
                return true;
            case LUA_TNUMBER:
                encodeNumber(lua_tonumber(L, idx));
                return true;
            case LUA_TSTRING: {
                size_t len = 0;
                const char* s = lua_tolstring(L, idx, &len);
                writeByte(kMarkerString);
                return writeUtf8Vr(s, len);
            }
            case LUA_TTABLE:
                return encodeTable(idx, depth);
            default:
                err.set("amf3.encode: unsupported Lua type '%s'", lua_typename(L, type));
                return false;
        }
    }
};

struct Amf3TraitInfo {
    std::string className;
    bool externalizable = false;
    bool dynamic = false;
    std::vector<std::string> sealedMembers;
};

struct LuaAmf3Decoder {
    lua_State* L = nullptr;
    const uint8_t* data = nullptr;
    size_t length = 0;
    size_t pos = 0;

    std::vector<std::string> stringRefs;
    std::vector<Amf3TraitInfo> traitRefs;
    int objRefTableIdx = 0;
    int objRefCount = 0;
    Amf3ErrorState err;

    bool ensureAvailable(size_t n) {
        if (n > length || pos > length - n) {
            err.set("amf3.decode: unexpected end of input at offset %d", static_cast<int>(pos));
            return false;
        }
        return true;
    }

    bool readByte(uint8_t& out) {
        if (!ensureAvailable(1)) return false;
        out = data[pos++];
        return true;
    }

    bool readU29(uint32_t& out) {
        if (!readU29Checked(data, length, pos, out)) {
            err.set("amf3.decode: unexpected end of input at offset %d", static_cast<int>(pos));
            return false;
        }
        return true;
    }

    bool readDoubleBE(double& out) {
        if (!readDoubleBEChecked(data, length, pos, out)) {
            err.set("amf3.decode: unexpected end of input at offset %d", static_cast<int>(pos));
            return false;
        }
        return true;
    }

    bool readUtf8Vr(std::string& out) {
        uint32_t header = 0;
        if (!readU29(header)) return false;
        if ((header & 1u) == 0u) {
            const uint32_t idx = header >> 1;
            if (idx >= stringRefs.size()) {
                err.set("amf3.decode: invalid string reference index %d", static_cast<int>(idx));
                return false;
            }
            out = stringRefs[idx];
            return true;
        }
        const size_t len = static_cast<size_t>(header >> 1);
        if (len == 0) {
            out.clear();
            return true;
        }
        if (!ensureAvailable(len)) return false;
        out.assign(reinterpret_cast<const char*>(data + pos), len);
        pos += len;
        stringRefs.push_back(out);
        return true;
    }

    bool pushObjectRef(uint32_t idx) {
        if (idx >= static_cast<uint32_t>(objRefCount)) {
            err.set("amf3.decode: invalid object reference index %d", static_cast<int>(idx));
            return false;
        }
        lua_rawgeti(L, objRefTableIdx, static_cast<int>(idx) + 1);
        return true;
    }

    void registerTopObjectRef() {
        ++objRefCount;
        lua_pushvalue(L, -1);
        lua_rawseti(L, objRefTableIdx, objRefCount);
    }

    bool readHeaderOrPushRef(uint32_t& headerOut, bool& pushedRef) {
        pushedRef = false;
        if (!readU29(headerOut)) return false;
        if ((headerOut & 1u) == 0u) {
            pushedRef = true;
            return pushObjectRef(headerOut >> 1);
        }
        return true;
    }

    bool decodeDynamicPairsIntoTopTable(int depth) {
        std::string key;
        for (;;) {
            if (!readUtf8Vr(key)) return false;
            if (key.empty()) return true;
            if (!lua_checkstack(L, 8)) {
                err.set("amf3: Lua stack overflow");
                return false;
            }
            lua_pushlstring(L, key.data(), key.size());
            if (!decodeValue(depth + 1)) return false;
            lua_rawset(L, -3);
        }
    }

    bool decodeXmlOrByteArray() {
        uint32_t header = 0;
        bool pushedRef = false;
        if (!readHeaderOrPushRef(header, pushedRef)) return false;
        if (pushedRef) return true;
        const size_t len = static_cast<size_t>(header >> 1);
        if (!ensureAvailable(len)) return false;
        lua_pushlstring(L, reinterpret_cast<const char*>(data + pos), len);
        pos += len;
        registerTopObjectRef();
        return true;
    }

    bool decodeDate() {
        uint32_t header = 0;
        bool pushedRef = false;
        if (!readHeaderOrPushRef(header, pushedRef)) return false;
        if (pushedRef) return true;
        double ms = 0.0;
        if (!readDoubleBE(ms)) return false;
        lua_pushnumber(L, ms);
        registerTopObjectRef();
        return true;
    }

    bool decodeArray(int depth) {
        uint32_t header = 0;
        bool pushedRef = false;
        if (!readHeaderOrPushRef(header, pushedRef)) return false;
        if (pushedRef) return true;

        const uint32_t denseCount = header >> 1;
        const size_t remWire = (pos <= length) ? (length - pos) : 0u;
        if (static_cast<size_t>(denseCount) > remWire) {
            err.set("amf3.decode: truncated dense array (count=%u, remaining=%u)",
                    static_cast<unsigned>(denseCount), static_cast<unsigned>(remWire));
            return false;
        }
        lua_createtable(L, denseCount > 4096u ? 4096 : static_cast<int>(denseCount), 0);
        registerTopObjectRef();

        if (!decodeDynamicPairsIntoTopTable(depth)) return false;

        for (uint32_t i = 1; i <= denseCount; ++i) {
            if (!lua_checkstack(L, 8)) {
                err.set("amf3: Lua stack overflow");
                return false;
            }
            if (!decodeValue(depth + 1)) return false;
            lua_rawseti(L, -2, static_cast<int>(i));
        }
        return true;
    }

    bool decodeObject(int depth) {
        uint32_t header = 0;
        bool pushedRef = false;
        if (!readHeaderOrPushRef(header, pushedRef)) return false;
        if (pushedRef) return true;

        Amf3TraitInfo traits;
        if ((header & 0x02u) == 0u) {
            const uint32_t traitIdx = header >> 2;
            if (traitIdx >= traitRefs.size()) {
                err.set("amf3.decode: invalid trait reference index %d", static_cast<int>(traitIdx));
                return false;
            }
            traits = traitRefs[traitIdx];
        } else {
            traits.externalizable = ((header & 0x04u) != 0u);
            traits.dynamic = ((header & 0x08u) != 0u);
            const uint32_t sealedCount = header >> 4;
            if (!readUtf8Vr(traits.className)) return false;
            const size_t remWire = (pos <= length) ? (length - pos) : 0u;
            if (static_cast<size_t>(sealedCount) > remWire) {
                err.set("amf3.decode: truncated object traits (sealedCount=%u)", static_cast<unsigned>(sealedCount));
                return false;
            }
            traits.sealedMembers.reserve(sealedCount > 1024u ? 1024u : sealedCount);
            for (uint32_t i = 0; i < sealedCount; ++i) {
                std::string member;
                if (!readUtf8Vr(member)) return false;
                traits.sealedMembers.push_back(std::move(member));
            }
            traitRefs.push_back(traits);
        }

        const int nrec = traits.sealedMembers.size() > 65536u
            ? 65536
            : static_cast<int>(traits.sealedMembers.size());
        lua_createtable(L, 0, nrec);
        registerTopObjectRef();

        if (traits.externalizable) {
            if (!decodeValue(depth + 1)) return false;
            lua_setfield(L, -2, "_external");
            return true;
        }

        for (const auto& memberName : traits.sealedMembers) {
            if (!lua_checkstack(L, 8)) {
                err.set("amf3: Lua stack overflow");
                return false;
            }
            lua_pushlstring(L, memberName.data(), memberName.size());
            if (!decodeValue(depth + 1)) return false;
            lua_rawset(L, -3);
        }

        return !traits.dynamic || decodeDynamicPairsIntoTopTable(depth);
    }

    bool decodeValue(int depth) {
        if (!lua_checkstack(L, 8)) {
            err.set("amf3: Lua stack overflow");
            return false;
        }
        if (depth > kMaxRecursionDepth) {
            err.set("amf3.decode: maximum nesting depth exceeded");
            return false;
        }

        uint8_t marker = 0;
        if (!readByte(marker)) return false;

        switch (marker) {
            case kMarkerUndefined:
            case kMarkerNull:
                lua_pushnil(L);
                return true;
            case kMarkerFalse:
                lua_pushboolean(L, 0);
                return true;
            case kMarkerTrue:
                lua_pushboolean(L, 1);
                return true;
            case kMarkerInteger: {
                uint32_t raw = 0;
                if (!readU29(raw)) return false;
                const int32_t val = (raw & 0x10000000u) != 0u
                    ? static_cast<int32_t>(raw | 0xE0000000u)
                    : static_cast<int32_t>(raw);
                lua_pushinteger(L, static_cast<lua_Integer>(val));
                return true;
            }
            case kMarkerDouble: {
                double d = 0.0;
                if (!readDoubleBE(d)) return false;
                lua_pushnumber(L, d);
                return true;
            }
            case kMarkerString: {
                std::string s;
                if (!readUtf8Vr(s)) return false;
                lua_pushlstring(L, s.data(), s.size());
                return true;
            }
            case kMarkerXmlDoc:
            case kMarkerXml:
            case kMarkerByteArray:
                return decodeXmlOrByteArray();
            case kMarkerDate:
                return decodeDate();
            case kMarkerArray:
                return decodeArray(depth);
            case kMarkerObject:
                return decodeObject(depth);
            default:
                err.set("amf3.decode: unsupported AMF3 type marker 0x%02X at offset %d",
                        static_cast<unsigned>(marker), static_cast<int>(pos - 1));
                return false;
        }
    }
};

} // namespace

extern "C" {

int amf3_encode(lua_State* L) {
    if (!lua_checkstack(L, 8)) {
        return luaL_error(L, "amf3: Lua stack overflow");
    }
    luaL_checkany(L, 1);
    lua_settop(L, 1);

    char errBuf[256] = {};
    bool ok = false;
    try {
        LuaAmf3Encoder encoder;
        encoder.L = L;
        encoder.out.reserve(128);
        ok = encoder.encodeValue(1, 0);
        if (ok) {
            lua_pushlstring(L, encoder.out.data(), encoder.out.size());
        } else {
            std::memcpy(errBuf, encoder.err.buf, sizeof(errBuf));
        }
    } catch (const std::bad_alloc&) {
        return luaL_error(L, "amf3.encode: out of memory");
    }
    return ok ? 1 : luaL_error(L, "%s", errBuf);
}

int amf3_decode(lua_State* L) {
    if (!lua_checkstack(L, 8)) {
        return luaL_error(L, "amf3: Lua stack overflow");
    }
    size_t len = 0;
    const char* str = luaL_checklstring(L, 1, &len);
    const lua_Integer posArg = luaL_optinteger(L, 2, 0);
    if (posArg < 0) {
        return luaL_argerror(L, 2, "position may not be negative");
    }

    lua_settop(L, 1);
    lua_createtable(L, 0, 0); // object reference table at stack index 2

    char errBuf[256] = {};
    bool ok = false;
    size_t finalPos = 0;
    try {
        LuaAmf3Decoder decoder;
        decoder.L = L;
        decoder.data = reinterpret_cast<const uint8_t*>(str);
        decoder.length = len;
        decoder.pos = static_cast<size_t>(posArg);
        decoder.objRefTableIdx = 2;

        ok = decoder.decodeValue(0);
        finalPos = decoder.pos;
        if (!ok) {
            std::memcpy(errBuf, decoder.err.buf, sizeof(errBuf));
        }
    } catch (const std::bad_alloc&) {
        return luaL_error(L, "amf3.decode: out of memory");
    }
    if (!ok) {
        return luaL_error(L, "%s", errBuf);
    }

    lua_pushinteger(L, static_cast<lua_Integer>(finalPos));
    return 2;
}

int luaopen_amf3(lua_State* L) {
    static const luaL_Reg kAmf3Funcs[] = {
        {"encode", amf3_encode},
        {"decode", amf3_decode},
        {nullptr, nullptr}
    };

    lua_createtable(L, 0, 2);
#if LUA_VERSION_NUM == 501
    luaL_register(L, nullptr, kAmf3Funcs);
#else
    luaL_setfuncs(L, kAmf3Funcs, 0);
#endif
    return 1;
}

int luaopen_amf3_extensions(lua_State* L) {
    lua_getglobal(L, "package");
    if (lua_istable(L, -1)) {
        lua_getfield(L, -1, "preload");
        if (lua_istable(L, -1)) {
            lua_pushcfunction(L, luaopen_amf3);
            lua_setfield(L, -2, "amf3");
        }
        lua_pop(L, 1);
    }
    lua_pop(L, 1);
    return 0;
}

} // extern "C"
