#pragma once

extern "C" {
#include "lauxlib.h"
#include "lua.h"
}

#include <string>

namespace gclient::bindings {

inline void InstallNetworkResilienceHookImpl(lua_State* L) {
    if (L == nullptr) return;

    // Split into <4 KB string literal chunks to stay strictly below MSVC /W4 C2026 (16,380-byte literal cap).
    static const char* const kLuaChunks[] = {
        R"LUA(
do
  if type(_G.__gclient_apply_net_resilience_sweep) == "function" then
    _G.__gclient_apply_net_resilience_sweep()
    return
  end

  local _unpack = unpack or table.unpack
  local function _weakMap() return setmetatable({}, { __mode = "k" }) end
  local _rawPushFns, _bdStates = _weakMap(), _weakMap()

  local function _patchMethodOnce(tbl, key, memo, makeWrapped)
    if type(tbl) ~= "table" then return end
    local cur = rawget(tbl, key)
    if type(cur) == "function" and memo[cur] then return end
    local wrapped = makeWrapped(cur)
    memo[wrapped] = cur or true
    tbl[key] = wrapped
  end

  local function _formatTraceback(errObj, level)
    local msg = tostring(errObj)
    if type(debug) == "table" and type(debug.traceback) == "function" and not string.find(msg, "stack traceback:", 1, true) then
      local ok, tb = pcall(debug.traceback, msg, level or 2)
      if ok and type(tb) == "string" and #tb > 0 then return tb end
    end
    return msg
  end

  local function _emitCCLuaLog(text)
    local full = "[NetResilience] " .. tostring(text)
    local fn = _G.CCLuaLog or _G.__GCLIENT_LOG_ERR__ or _G.release_print or _G.print
    if type(fn) == "function" then pcall(fn, full) end
  end

  local function _tbHandler(errObj)
    local full = _formatTraceback(errObj, 2)
    _emitCCLuaLog(full)
    return full
  end

  local function _isNodeDisposed(node)
    if node == nil then return true end
    local tp = type(node)
    if tp == "table" then return rawget(node, "_isDisposed") == true end
    if tp ~= "userdata" then return false end
    if getmetatable(node) == nil then return true end
    if tolua and type(tolua.isnull) == "function" then
      local ok, res = pcall(tolua.isnull, node)
      if ok and res then return true end
    end
    return false
  end

  local function _isUnderMainLoading(lm)
    return type(lm) == "table" and lm._mainLoading ~= nil and not _isNodeDisposed(lm._mainLoading)
  end

  local function _clearDataLoadingIfEmpty(lm, km)
    if (lm._dataLoadingShowCount or 0) < 0 then lm._dataLoadingShowCount = 0 end
    if (lm._dataLoadingShowCount or 0) <= 0 then
      local hasKey = false
      if type(lm._checkHasLoadingKey) == "function" then
        local okK, resK = pcall(lm._checkHasLoadingKey, lm)
        hasKey = (okK and resK == true)
      elseif type(km) == "table" then
        for _, v in pairs(km) do
          if type(v) == "number" and v > 0 then hasKey = true; break end
        end
      end
      if not hasKey and lm._curLoadingType == (lm.DATA_LOADING_TYPE or 1) and type(lm._forceClearDataLoading) == "function" then
        pcall(lm._forceClearDataLoading, lm)
      end
    end
  end

  local function _hideIdleLoadingOverlays()
    local lm = g and g.loadingManager
    if type(lm) == "table" and not _isUnderMainLoading(lm) then
      if type(lm.hideSwitchLoading) == "function" then xpcall(function() lm:hideSwitchLoading() end, _tbHandler) end
      if lm._curLoadingType == (lm.DATA_LOADING_TYPE or 1) and type(lm.hideDataLoading) == "function" then
        xpcall(function() lm:hideDataLoading() end, _tbHandler)
      end
    end
  end

  local function _safeHideDataLoadingKey(key)
    if key == nil then return end
    local lm = g and g.loadingManager
    if type(lm) ~= "table" then return end
    if type(lm.hideDataLoading) == "function" then
      xpcall(function() lm:hideDataLoading(key) end, _tbHandler)
    end
    if type(lm._dataLoadingKeyMap) == "table" and lm._dataLoadingKeyMap[key] ~= nil then
      if type(lm._delLoadingKey) == "function" then
        pcall(lm._delLoadingKey, lm, key)
      else
        lm._dataLoadingKeyMap[key] = nil
      end
)LUA",
        R"LUA(
      _clearDataLoadingIfEmpty(lm, nil)
    end
  end

  local function _reconcileLoadingKeys(netSelf, clearSelfPendingToo)
    local lm = g and g.loadingManager
    if type(lm) ~= "table" then return end
    local km = lm._dataLoadingKeyMap
    if type(km) == "table" then
      local toClear = {}
      local ctxMap = (type(netSelf) == "table" and type(netSelf.mContext) == "table") and netSelf.mContext or nil
      for k, _ in pairs(km) do
        if k ~= "showLoginProtect" then
          local ctx = ctxMap and ctxMap[k] or nil
          if clearSelfPendingToo or not (type(ctx) == "table" and ctx[3] == nil) then
            toClear[#toClear + 1] = k
          end
        end
      end
      for i = 1, #toClear do
        local k, guard = toClear[i], 0
        while km[k] ~= nil and guard < 16 do
          guard = guard + 1
          local before = km[k]
          if type(lm.hideDataLoading) == "function" then pcall(lm.hideDataLoading, lm, k) end
          if km[k] == before then km[k] = nil; break end
        end
      end
    end
    _clearDataLoadingIfEmpty(lm, km)
  end

  local function _getBdState(bd)
    local st = _bdStates[bd]
    if not st then
      st = { waiters = {}, hasParsedOk = (bd.isok == true), reqGen = 0 }
      _bdStates[bd] = st
    end
    return st
  end

  local function _enqueueBdWaiter(bd, st, cb)
    local legacy = bd._onReceiveData
    if legacy ~= nil then
      bd._onReceiveData = nil
      if type(legacy) == "function" then st.waiters[#st.waiters + 1] = legacy end
    end
    if type(cb) == "function" then st.waiters[#st.waiters + 1] = cb end
  end

  local function _drainBdWaiters(bd, st)
    local list = st.waiters
    st.waiters = {}
    local legacy = bd._onReceiveData
    if legacy ~= nil then
      bd._onReceiveData = nil
      if type(legacy) == "function" then table.insert(list, 1, legacy) end
    end
    for i = 1, #list do
      if type(list[i]) == "function" then xpcall(list[i], _tbHandler) end
    end
  end

  local function _resetBindableOnFailure(bd)
    if type(bd) ~= "table" and type(bd) ~= "userdata" then return end
    local st = _getBdState(bd)
    st.reqGen = (st.reqGen or 0) + 1
    bd._isloading = false
    if not st.hasParsedOk then bd.isok = false end
    _drainBdWaiters(bd, st)
  end

  local function _resetProxyOnFailure(proxy, expectedGen)
    if type(proxy) ~= "table" then return end
    if type(proxy._moduleRequestTime) == "number" and proxy._moduleRequestTime > 0 then
      proxy._moduleRequestTime = proxy._moduleRequestTime - 1
    end
    if type(proxy._finishCheckDataAvailableSafe) == "function" then
      xpcall(function() proxy:_finishCheckDataAvailableSafe(expectedGen) end, _tbHandler)
    else
      proxy._isCheckingData = false
      proxy._numUnavailable = 0
      proxy.dataAvialableCallback = nil
    end
  end

  local function _notifyRequestFailure(netSelf, ctx, errReason)
    if type(ctx) ~= "table" then return end
    local handledBd, handledProxy = {}, {}
    if ctx._bdOwner ~= nil then
      handledBd[ctx._bdOwner] = true
      _resetBindableOnFailure(ctx._bdOwner)
    end
    if ctx._proxyOwner ~= nil then
      handledProxy[ctx._proxyOwner] = true
      _resetProxyOnFailure(ctx._proxyOwner, ctx._proxyGen)
    end
    if type(ctx._onNetErrorCb) == "function" then
      xpcall(function() ctx._onNetErrorCb(errReason) end, _tbHandler)
    end
    local cb = ctx[1]
    local rawCb = (type(cb) == "function" and (_rawPushFns[cb] or cb)) or nil
    if type(rawCb) == "function" and type(debug) == "table" and type(debug.getupvalue) == "function" then
      for idx = 1, 8 do
        local okUv, uName, uVal = pcall(debug.getupvalue, rawCb, idx)
)LUA",
        R"LUA(
        if not okUv or uName == nil then break end
        if type(uVal) == "table" then
          if not handledBd[uVal] and uVal._isloading == true and type(uVal.parseData) == "function" and type(uVal.initdata) == "function" then
            handledBd[uVal] = true
            _resetBindableOnFailure(uVal)
          elseif not handledProxy[uVal] and (type(uVal._onModuleDataAvailable) == "function" or type(uVal.checkDataAvialable) == "function") then
            handledProxy[uVal] = true
            _resetProxyOnFailure(uVal, nil)
          end
        end
      end
    end
  end

  local function _cancelInFlightWatchdog(netSelf, cbKey)
    if not cbKey or type(netSelf) ~= "table" or type(netSelf._inFlightWatchdogs) ~= "table" then return end
    local tid = netSelf._inFlightWatchdogs[cbKey]
    if tid ~= nil then
      netSelf._inFlightWatchdogs[cbKey] = nil
      if g and g.timerManager and type(g.timerManager.removeTimer) == "function" then
        pcall(g.timerManager.removeTimer, g.timerManager, tid)
      end
    end
  end

  local function _dropPendingContext(netSelf, cbKey)
    if not cbKey or type(netSelf) ~= "table" then return end
    _cancelInFlightWatchdog(netSelf, cbKey)
    if type(netSelf.mContext) == "table" then netSelf.mContext[cbKey] = nil end
    if type(netSelf._timestamp_map) == "table" then netSelf._timestamp_map[cbKey] = nil end
  end

  local function _applyEnvelopeTokenAndTime(netSelf, tok, ts, isPrimary)
    if tok ~= nil then netSelf.mToken = tok end
    if isPrimary and type(ts) == "number" then
      netSelf.mOffset = ts - os.time()
      if g and g.timeManager and type(g.timeManager.setOffset) == "function" then
        xpcall(function() g.timeManager:setOffset(netSelf.mOffset) end, _tbHandler)
      end
    end
  end

  local function _wrapPushCallback(fn)
    if type(fn) ~= "function" then return fn end
    local orig = _rawPushFns[fn] or fn
    local wrapped = function(...)
      local argc, argv = select("#", ...), { ... }
      local ok, res = xpcall(function() return orig(_unpack(argv, 1, argc)) end, _tbHandler)
      if ok then return res end
      return nil
    end
    _rawPushFns[wrapped] = orig
    return wrapped
  end

  local function _resolveAmf3()
    if type(_G.amf3) == "table" then return _G.amf3 end
    if type(package) == "table" and type(package.loaded) == "table" then
      return package.loaded.amf3 or package.loaded["scripts/amf3"]
    end
    return nil
  end

  local function _patchNetworkTarget(target, isPrimary)
    if type(target) ~= "table" or rawget(target, "_patchedGClientNetResilience") then return end
    rawset(target, "_patchedGClientNetResilience", true)
    rawset(target, "_patchedSafeNetworkV15", true)

    local origRegPush = rawget(target, "_origCleanRegPushCallback") or target.regPushCallback
    rawset(target, "_origCleanRegPushCallback", origRegPush)

    if type(target.mContext) == "table" then
      for _, ctx in pairs(target.mContext) do
        if type(ctx) == "table" and ctx[3] ~= nil and type(ctx[1]) == "function" and not ctx._gclientWrappedPush then
          ctx._gclientWrappedPush = true
          ctx[1] = _wrapPushCallback(ctx[1])
        end
      end
    end

    if type(origRegPush) == "function" then
      target.regPushCallback = function(self, method, callback, isForce, ...)
        if method == nil then return nil end
        local safeCb = _wrapPushCallback(callback)
        local argc, argv = select("#", ...), { ... }
        local ok, res = xpcall(function()
          return origRegPush(self, method, safeCb, isForce, _unpack(argv, 1, argc))
        end, _tbHandler)
)LUA",
        R"LUA(
        if type(self.mContext) == "table" and type(self.mContext[method]) == "table" then
          self.mContext[method]._gclientWrappedPush = true
        end
        return ok and res or nil
      end
    end

    target.onClosed = function(self)
      self._activeConnToken = nil
      self._deferredTxQueue = {}
      self._txFlushScheduled = false
      if g and g.networkUtil and type(g.networkUtil.stop) == "function" then
        xpcall(function() g.networkUtil:stop() end, _tbHandler)
      end
      self.mConn = nil
      self._timestamp_map = {}
      self._timestamp_last_send = nil

      local closedKey = self.kETClosedEvent or "Network.onClosed"
      if type(self.mContext) == "table" and type(self.mContext[closedKey]) == "table" and type(self.mContext[closedKey][1]) == "function" then
        xpcall(self.mContext[closedKey][1], _tbHandler)
      end

      if isPrimary then
        if g and g.mainData and type(g.mainData.networkCloseResetDatas) == "function" then
          xpcall(function() g.mainData:networkCloseResetDatas() end, _tbHandler)
        end
        if type(sendNotification) == "function" and g and g.noteConst and g.noteConst.NETWORK_CLOSE ~= nil then
          xpcall(function() sendNotification(g.noteConst.NETWORK_CLOSE) end, _tbHandler)
        end
        _reconcileLoadingKeys(self, true)
      end

      local firstPendingName = nil
      if type(self.mContext) == "table" then
        for name, ctx in pairs(self.mContext) do
          if type(ctx) == "table" and ctx[3] == nil then firstPendingName = name; break end
        end
      end

      if isPrimary then
        _hideIdleLoadingOverlays()
        if firstPendingName ~= nil and type(self.goReconnect) == "function" then
          xpcall(function() self:goReconnect("onClosed:" .. tostring(firstPendingName)) end, _tbHandler)
        end
      end
    end

    target.sendMsg = function(self, method, callback, args, isNotShowLoading, ...)
      self._lastSentCbKey = nil
      local proxyOwner, proxyGen = self._activeProxyRequestOwner, self._activeProxyRequestGen
      local bdOwner, bdErrCb = self._activeBindableDataOwner, self._activeBindableDataErrorCb

      local function abortEarly(reason)
        if proxyOwner then proxyOwner._lastModuleSendSkipped = true end
        if bdOwner then _resetBindableOnFailure(bdOwner) end
        if type(bdErrCb) == "function" then xpcall(function() bdErrCb(reason) end, _tbHandler) end
        return nil
      end

      local methodStr = type(method) == "table" and method[#method] or method
      if type(methodStr) ~= "string" or methodStr == "" then
        return abortEarly("invalid_method")
      end

      if self.mConn == nil then
        self.msgs_unused = self.msgs_unused or {}
        table.insert(self.msgs_unused, { methodStr, callback, args, isNotShowLoading })
        if isPrimary then
          _reconcileLoadingKeys(self, false)
          _hideIdleLoadingOverlays()
          if #self.msgs_unused <= 1 and type(self.goReconnect) == "function" then
            xpcall(function() self:goReconnect("sendMsg:" .. methodStr) end, _tbHandler)
          end
        end
        return nil
      end

      if isPrimary then
        local okRp, rpMod = pcall(require, "game.modules.reconnect.ReconnectProxy")
        if okRp and type(rpMod) == "table" and type(rpMod.ins) == "function" then
          local okIns, rpIns = pcall(rpMod.ins, rpMod)
          if okIns and type(rpIns) == "table" and type(rpIns.isBanSendMsg) == "function" then
            local okBan, isBanned = pcall(rpIns.isBanSendMsg, rpIns, methodStr)
            if okBan and isBanned then return abortEarly("banned_during_reconnect") end
          end
)LUA",
        R"LUA(
        end
      end

      self.mId = (self.mId or 0) + 1
      local callbackName = methodStr .. "_" .. tostring(self.mId)

      local lm = isPrimary and g and g.loadingManager or nil
      if not (isNotShowLoading == true or _isUnderMainLoading(lm)) and type(lm) == "table" and type(lm.showDataLoading) == "function" then
        xpcall(function() lm:showDataLoading(callbackName) end, _tbHandler)
      end

      local request = {
        method = methodStr,
        args = (args ~= nil) and args or {},
        token = self.mToken,
        callback = { callbackName = callbackName }
      }

      self.mContext = self.mContext or {}
      local ctxEntry = { callback, args, nil, request, _bdOwner = bdOwner, _proxyOwner = proxyOwner, _proxyGen = proxyGen }
      if type(bdErrCb) == "function" then ctxEntry._onNetErrorCb = bdErrCb end
      if proxyOwner and type(proxyOwner._finishCheckDataAvailableSafe) == "function" then
        local prevErr = ctxEntry._onNetErrorCb
        ctxEntry._onNetErrorCb = function(reason)
          if type(prevErr) == "function" then xpcall(function() prevErr(reason) end, _tbHandler) end
          xpcall(function() proxyOwner:_finishCheckDataAvailableSafe(proxyGen) end, _tbHandler)
        end
      end

      self.mContext[callbackName] = ctxEntry
      self._lastSentCbKey = callbackName
      self._timestamp_map = self._timestamp_map or {}
      local nowTs = os.time()
      self._timestamp_map[callbackName] = nowTs
      self._timestamp_last_send = nowTs

      local function cleanupFailedSend(reason)
        _dropPendingContext(self, callbackName)
        if self._lastSentCbKey == callbackName then self._lastSentCbKey = nil end
        if isPrimary then _safeHideDataLoadingKey(callbackName) end
        if proxyOwner then proxyOwner._lastModuleSendSkipped = true end
        _notifyRequestFailure(self, ctxEntry, reason)
      end

      if isPrimary and g and g.networkUtil and type(g.networkUtil.start) == "function" then
        xpcall(function() g.networkUtil:start() end, _tbHandler)
      end

      local amf3Mod = _resolveAmf3()
      if type(amf3Mod) ~= "table" or type(amf3Mod.encode) ~= "function" then
        _emitCCLuaLog(_formatTraceback("Network:sendMsg amf3.encode unavailable for " .. callbackName, 2))
        cleanupFailedSend("amf3_unavailable")
        return nil
      end

      local encOk, encoded = xpcall(function() return amf3Mod.encode(request) end, _tbHandler)
      if not encOk or type(encoded) ~= "string" or #encoded == 0 then
        if encOk then
          _emitCCLuaLog(_formatTraceback("Network:sendMsg amf3.encode returned empty/non-string for " .. callbackName, 2))
        end
        cleanupFailedSend("encode_failed")
        return nil
      end

      if isPrimary then
        local sr = rawget(self, "SafetyRadarProxy") or (package and type(package.loaded) == "table" and package.loaded["game/modules/safetyRadar/SafetyRadarProxy"] and package.loaded["game/modules/safetyRadar/SafetyRadarProxy"]._ins)
        if type(sr) == "table" and sr.isCaptureMsg and type(sr.insertMsg) == "function" then
          xpcall(function() sr:insertMsg(request) end, _tbHandler)
        end
      end

      local conn = self.mConn
      if conn == nil or type(conn.send) ~= "function" then
        _emitCCLuaLog(_formatTraceback("Network:sendMsg mConn became nil before send for " .. callbackName, 2))
        cleanupFailedSend("conn_nil")
        return nil
      end

      local sendOk, sendRes = xpcall(function() return conn:send(encoded, true) end, _tbHandler)
      if not sendOk or sendRes == false then
        if sendOk then
)LUA",
        R"LUA(
          _emitCCLuaLog(_formatTraceback("Network:sendMsg mConn:send returned false for " .. callbackName, 2))
        end
        cleanupFailedSend("send_failed")
        return nil
      end

      if g and g.isDebug and g.util and type(g.util.tableToString) == "function" and type(print) == "function" then
        pcall(function() print("clint ================> server", callbackName, g.util:tableToString(args)) end)
      end
      return callbackName
    end

    target.onBodyData = function(self, body, head)
      self._inOnBodyDataDepth = (self._inOnBodyDataDepth or 0) + 1
      local function failBody(msg)
        if msg then _emitCCLuaLog(_formatTraceback(msg, 2)) end
        if isPrimary then _reconcileLoadingKeys(self, false) end
      end

      local function processPacket()
        local zipped, multi = 0, 0
        if type(head) == "string" and #head >= 7 then
          zipped, multi = string.byte(head, 6, 7)
        end

        local payload = body
        if zipped ~= nil and zipped ~= 0 then
          if type(body) ~= "string" or #body == 0 then
            return failBody("Network:onBodyData zipped~=0 with empty/non-string body")
          end
          if not (GameUtil and type(GameUtil.unzipData) == "function") then
            return failBody("Network:onBodyData GameUtil:unzipData missing")
          end
          local uzOk, unzipped = xpcall(function() return GameUtil:unzipData(body) end, _tbHandler)
          if not uzOk or type(unzipped) ~= "string" or #unzipped == 0 then
            return failBody(uzOk and "Network:onBodyData GameUtil:unzipData returned empty string" or nil)
          end
          payload = unzipped
        end

        local amf3Mod = _resolveAmf3()
        local data = payload
        if type(payload) ~= "table" then
          if type(payload) ~= "string" or #payload == 0 or type(amf3Mod) ~= "table" or type(amf3Mod.decode) ~= "function" then
            return failBody("Network:onBodyData invalid payload or missing amf3.decode")
          end
          local decOk, decoded = xpcall(function() return amf3Mod.decode(payload) end, _tbHandler)
          if not decOk or type(decoded) ~= "table" then
            return failBody(decOk and ("Network:onBodyData outer amf3.decode returned non-table: " .. tostring(decoded)) or nil)
          end
          data = decoded
        end

        local rets = {}
        if multi ~= nil and multi ~= 0 then
          if type(data.ret) ~= "table" then
            return failBody("Network:onBodyData multi~=0 with non-table data.ret (" .. type(data.ret) .. ")")
          end
          for i = 1, #data.ret do
            local rawSub = data.ret[i]
            if type(rawSub) == "table" then
              rets[#rets + 1] = rawSub
            elseif type(rawSub) == "string" and #rawSub > 0 and type(amf3Mod) == "table" and type(amf3Mod.decode) == "function" then
              local subOk, subDecoded = xpcall(function() return amf3Mod.decode(rawSub) end, _tbHandler)
              if subOk and type(subDecoded) == "table" then
                rets[#rets + 1] = subDecoded
              elseif subOk then
                _emitCCLuaLog(_formatTraceback("Network:onBodyData sub-packet #" .. tostring(i) .. " decoded non-table", 2))
              end
            else
              _emitCCLuaLog(_formatTraceback("Network:onBodyData malformed sub-packet #" .. tostring(i) .. " (" .. type(rawSub) .. ")", 2))
            end
          end
        else
          rets[1] = data
        end

        _applyEnvelopeTokenAndTime(self, data.token, data.time, isPrimary)

        if #rets == 0 then
)LUA",
        R"LUA(
          if Logger and type(Logger.showFatal) == "function" then pcall(Logger.showFatal, "onBodyData rets invalid") end
          if isPrimary then _reconcileLoadingKeys(self, false) end
          return
        end

        for i = 1, #rets do
          local preRet = rets[i]
          local preCbName = (type(preRet) == "table" and type(preRet.callback) == "table") and preRet.callback.callbackName or nil
          local hidLoadingForSub = false

          local subLoopOk = xpcall(function()
            if Logger and type(Logger.showTrace) == "function" then pcall(Logger.showTrace, "this is ret:") end
            local ret = rets[i]
            if type(ret) ~= "table" then return end
            if g and g.isDebug and g.util and type(g.util.dump) == "function" then pcall(g.util.dump, ret) end
            if ret.err == "ping" then return end

            _applyEnvelopeTokenAndTime(self, data.token == nil and ret.token or nil, data.time == nil and ret.time or nil, isPrimary)
            self._timestamp_last_send = nil

            local callbackName = (type(ret.callback) == "table") and ret.callback.callbackName or nil
            local context = (callbackName ~= nil and type(self.mContext) == "table") and self.mContext[callbackName] or nil

            if ret.err == "ok" and context ~= nil then
              if g and g.isQASimulation and type(self.log_print) == "table" then
                table.insert(self.log_print, { callbackName = ret })
              end
              local callback, args = context[1], context[2]
              if context[3] == nil then
                _dropPendingContext(self, callbackName)
                if g and g.isDebug and type(print) == "function" then
                  pcall(print, "server ================> clint", callbackName)
                end
              end
              if type(callback) == "function" then
                local rawFn = _rawPushFns[callback] or callback
                xpcall(function() rawFn(ret.ret, args) end, _tbHandler)
              end
              if isPrimary and callbackName ~= nil then
                hidLoadingForSub = true
                _safeHideDataLoadingKey(callbackName)
              end
            else
              if type(print) == "function" then
                pcall(print, string.format("callbackName:%s, err:%s", tostring(callbackName), tostring(ret.err)))
              end
              if ret.err ~= "ok" then
                if callbackName ~= nil and (context == nil or context[3] == nil) then
                  _dropPendingContext(self, callbackName)
                end
                if isPrimary then
                  hidLoadingForSub = true
                  if callbackName ~= nil then _safeHideDataLoadingKey(callbackName) else _reconcileLoadingKeys(self, false) end
                end

                local hostVal = (g and g.host)
                if hostVal == nil then hostVal = self.host end
                local msg = string.format(
                  "callbackName: %s\nhost:%s\npid:%s\ntoken:%s\nerr: %s",
                  tostring(callbackName), tostring(hostVal), tostring(g and g.pid), tostring(self.mToken), tostring(ret.err)
                )
                local prefix = "Error: "
                if type(lang) == "function" then
                  local okLang, resLang = pcall(lang, "translate_1295")
                  if okLang and resLang ~= nil then prefix = tostring(resLang) end
                end
                if not _isUnderMainLoading(g and g.loadingManager) and type(CCMessageBox) == "function" then
                  pcall(CCMessageBox, msg, prefix .. tostring(ret.err))
                end
)LUA",
        R"LUA(
                if context ~= nil then _notifyRequestFailure(self, context, ret.err) end
              elseif isPrimary and callbackName ~= nil then
                hidLoadingForSub = true
                _safeHideDataLoadingKey(callbackName)
              end
            end
          end, _tbHandler)

          if not subLoopOk and isPrimary and not hidLoadingForSub and preCbName ~= nil then
            _safeHideDataLoadingKey(preCbName)
          end
        end
      end

      xpcall(processPacket, _tbHandler)
      local depth = (self._inOnBodyDataDepth or 1) - 1
      self._inOnBodyDataDepth = depth < 0 and 0 or depth
    end
  end

  local function _patchNetworkModule(netMod, isPrimary)
    if type(netMod) ~= "table" then return end
    _patchNetworkTarget(netMod, isPrimary)

    if not rawget(netMod, "_patchedGClientNetFactory") then
      rawset(netMod, "_patchedGClientNetFactory", true)
      for _, ctorKey in ipairs({ "ins", "new" }) do
        local origFn = netMod[ctorKey]
        if type(origFn) == "function" then
          netMod[ctorKey] = function(self, ...)
            local inst = origFn(self, ...)
            if type(inst) == "table" then _patchNetworkTarget(inst, isPrimary) end
            return inst
          end
        end
      end
    end

    local existingIns = rawget(netMod, "_ins")
    if type(existingIns) == "table" then _patchNetworkTarget(existingIns, isPrimary) end
    if isPrimary and g and type(g.network) == "table" then _patchNetworkTarget(g.network, true) end
  end

  local function _bindableInitdata(self, callback)
    local st = _getBdState(self)
    _enqueueBdWaiter(self, st, callback)
    if self._isloading == true then return end

    if Logger and type(Logger.showTrace) == "function" and type(self.toString) == "function" then
      pcall(function() Logger.showTrace(tostring(self:toString()) .. " fetch") end)
    end

    local function failInit()
      self._isloading = false
      if not st.hasParsedOk then self.isok = false end
      _drainBdWaiters(self, st)
    end

    local okMn, mn = xpcall(function() return self:methodName() end, _tbHandler)
    if not okMn then return failInit() end
    if mn == "" or mn == nil then
      self._isloading = false
      self:onReceiveData(nil, nil)
      return
    end

    local net = (g and g.network)
    if type(net) ~= "table" and self.network and type(self.network.ins) == "function" then
      local okN, nIns = pcall(self.network.ins, self.network)
      if okN and type(nIns) == "table" then net = nIns end
    end
    if type(net) ~= "table" or type(net.sendMsg) ~= "function" then return failInit() end
    if not rawget(net, "_patchedGClientNetResilience") then _patchNetworkTarget(net, true) end

    local okArgs, mArgs = xpcall(function() return self:methodArgs() end, _tbHandler)
    if not okArgs or mArgs == nil then mArgs = {} end

    st.reqGen = (st.reqGen or 0) + 1
    local myGen, completed = st.reqGen, false
    self._isloading = true

    local function onFail()
      if not completed and st.reqGen == myGen then
        st.reqGen = myGen + 1
        failInit()
      end
    end

    local prevMid = net.mId or 0
    net._activeBindableDataOwner, net._activeBindableDataErrorCb = self, onFail
    local sendOk, sentKey = xpcall(function()
      return net:sendMsg(mn, function(ret, args)
        completed = true
        self:onReceiveData(ret, args)
      end, mArgs)
    end, _tbHandler)
    net._activeBindableDataOwner, net._activeBindableDataErrorCb = nil, nil

    if not sendOk then return onFail() end
    if not completed then
      local key = (type(sentKey) == "string" and sentKey) or net._lastSentCbKey
)LUA",
        R"LUA(
      if not key and (net.mId or 0) > prevMid then
        local mStr = type(mn) == "table" and mn[#mn] or mn
        key = tostring(mStr) .. "_" .. tostring(net.mId)
      end
      local ctx = (key and type(net.mContext) == "table") and net.mContext[key] or nil
      if type(ctx) == "table" then
        ctx._bdOwner = self
        if ctx._onNetErrorCb == nil then ctx._onNetErrorCb = onFail end
      elseif net.mConn ~= nil or type(net.goReconnect) ~= "function" then
        onFail()
      end
    end
  end

  local function _bindableOnReceiveData(self, ret, args)
    local st = _getBdState(self)
    st.reqGen = (st.reqGen or 0) + 1
    if Logger and type(Logger.showTrace) == "function" and type(self.toString) == "function" then
      pcall(function() Logger.showTrace(tostring(self:toString()) .. " recv") end)
    end
    local parseOk = xpcall(function() self:parseData(ret) end, _tbHandler)
    self._isloading = false
    if parseOk then
      st.hasParsedOk, self.isok = true, true
    else
      self.isok = st.hasParsedOk and true or false
    end
    _drainBdWaiters(self, st)
  end

  local function _bindableResetState(self)
    local st = _bdStates[self]
    if st then
      st.reqGen = (st.reqGen or 0) + 1
      st.hasParsedOk, st.waiters = false, {}
    end
    local okMn, mn = pcall(self.methodName, self)
    if not okMn or mn == "" or mn == nil then return end
    self._isloading, self.isok = false, false
  end

  local function _bindableUnbindSetter(self, property, instance)
    if instance == nil then return end
    local cmap = self._bindPropertyMap and self._bindPropertyMap[property]
    if type(cmap) == "table" then cmap[instance] = nil end
  end

  local function _bindableDobindCallback(self, property, value)
    local cmap = self._bindPropertyMap and self._bindPropertyMap[property]
    if type(cmap) ~= "table" then return end
    local snap = {}
    for inst, cb in pairs(cmap) do snap[#snap + 1] = { inst, cb } end
    for i = 1, #snap do
      local inst, cb = snap[i][1], snap[i][2]
      if inst ~= nil and (type(inst) == "userdata" or type(inst) == "table") and _isNodeDisposed(inst) then
        cmap[inst] = nil
      elseif type(cb) == "function" then
        xpcall(function() cb(inst, value) end, _tbHandler)
      end
    end
  end

  local function _patchBindableClass(bdTbl)
    if type(bdTbl) ~= "table" or rawget(bdTbl, "_patchedGClientBindableResilience") then return end
    rawset(bdTbl, "_patchedGClientBindableResilience", true)
    rawset(bdTbl, "_patchedSafeBindableV15", true)
    bdTbl.initdata = _bindableInitdata
    bdTbl.onReceiveData = _bindableOnReceiveData
    bdTbl.resetState = _bindableResetState
    bdTbl.unbindSetter = _bindableUnbindSetter
    bdTbl.dobindCallback = _bindableDobindCallback
  end

  local function _patchBaseProxyModule(bpMod)
    if type(bpMod) ~= "table" then return end
    if not rawget(bpMod, "_patchedGClientBaseProxyResilience") then
      rawset(bpMod, "_patchedGClientBaseProxyResilience", true)
      if type(bpMod._finishCheckDataAvailableSafe) ~= "function" and type(bpMod._moduleRequest) == "function" then
        local origModReq = bpMod._moduleRequest
        bpMod._moduleRequest = function(self, ...)
          local net = g and g.network
          if type(net) == "table" then net._activeProxyRequestOwner = self end
          local argc, argv = select("#", ...), { ... }
          local ok, res = xpcall(function() return origModReq(self, _unpack(argv, 1, argc)) end, _tbHandler)
          if type(net) == "table" and net._activeProxyRequestOwner == self then net._activeProxyRequestOwner = nil end
          if not ok then _resetProxyOnFailure(self, nil) end
)LUA",
        R"LUA(
          return res
        end
      end
    end

    local v11Fn = rawget(_G, "__ensureStuck99LoadingFlowGuardsV11")
    if type(v11Fn) == "function" and not _rawPushFns[v11Fn] then
      local wrappedV11 = function(...)
        local ok, res = pcall(v11Fn, ...)
        if type(_G.__gclient_apply_net_resilience_sweep) == "function" then pcall(_G.__gclient_apply_net_resilience_sweep) end
        if ok then return res end
      end
      _rawPushFns[wrappedV11] = v11Fn
      _G.__ensureStuck99LoadingFlowGuardsV11 = wrappedV11
      _G.__ensureCrash4LoadingToTownUafGuardsV12 = wrappedV11
    end
  end

  local function _normalizeVngPlatform(pl)
    if pl == "vngios" then return "vngios" end
    if pl == nil or pl == "" or pl == "android" or pl == "vnsg2" or pl == "android_vnsg2" or pl == "win32" then
      return "vngandroid"
    end
    return pl
  end

  local function _normalizeUserDataTarget(ud)
    if type(ud) ~= "table" and type(ud) ~= "userdata" then return end
    pcall(function() ud.platform = _normalizeVngPlatform(ud.platform) end)
  end

  local function _patchUserDataModule(udMod)
    if type(udMod) ~= "table" or rawget(udMod, "_patchedGClientVngUserData") then return end
    rawset(udMod, "_patchedGClientVngUserData", true)
    rawset(udMod, "platform", _normalizeVngPlatform(rawget(udMod, "platform")))
    for _, fnName in ipairs({ "ctor", "parseData", "onUpdateUser" }) do
      local origFn = rawget(udMod, fnName)
      if type(origFn) == "function" then
        udMod[fnName] = function(self, ...)
          local r1, r2, r3 = origFn(self, ...)
          _normalizeUserDataTarget(self)
          return r1, r2, r3
        end
      end
    end
  end

  local function _getPayPairCandidates(numId)
    if (numId >= 1600 and numId <= 1699) or (numId >= 1800 and numId <= 1899) then return { numId + 100 }
    elseif (numId >= 1700 and numId <= 1799) or (numId >= 1900 and numId <= 1999) then return { numId - 100 }
    elseif numId >= 1001 and numId <= 1099 then return { numId + 100, numId + 200 }
    elseif numId >= 1201 and numId <= 1299 then return { numId - 100, numId - 200 }
    elseif numId >= 1101 and numId <= 1199 then return { numId - 100, numId + 100 } end
    return {}
  end

  local function _probePayReaderRaw(self, origFn, candidateId, ...)
    if type(origFn) ~= "function" then return nil end
    local loggerTbl = rawget(_G, "Logger")
    local origFatal = type(loggerTbl) == "table" and loggerTbl.showFatal or nil
    if type(origFatal) == "function" then loggerTbl.showFatal = function() end end
    local ok, row = pcall(origFn, self, candidateId, ...)
    if origFatal ~= nil then loggerTbl.showFatal = origFatal end
    return (ok and type(row) == "table") and row or nil
  end

  local _wrappedPayGetRowFns = _weakMap()
  local function _patchPayReaderTarget(prTbl)
    if type(prTbl) ~= "table" then return end
    local curFn = prTbl.getRowById
    if type(curFn) == "function" and _wrappedPayGetRowFns[curFn] then return end
    local wrapped = function(self, id, ...)
      local numId = id ~= nil and tonumber(id) or nil
      if numId == nil then return nil end
      if numId <= 0 then return _probePayReaderRaw(self, curFn, numId, ...) end
      local row = _probePayReaderRaw(self, curFn, numId, ...)
      if row then return row end
      local cands = _getPayPairCandidates(numId)
      for i = 1, #cands do
        local altRow = _probePayReaderRaw(self, curFn, cands[i], ...)
        if altRow then return altRow end
      end
      return { id = numId, is_open = 1, recharge_type = 5, consume_money = 0, currency_name = "VND", title = "Gift", des = "", vip_exp = 0 }
    end
)LUA",
        R"LUA(
    _wrappedPayGetRowFns[wrapped] = curFn or true
    prTbl.getRowById = wrapped
  end

  local function _plainLuaCopy(val, depth)
    local d = depth or 0
    if d > 6 then return nil end
    local vt = type(val)
    if vt == "number" or vt == "string" or vt == "boolean" or vt == "nil" then return val end
    if vt ~= "table" then return nil end
    local out = {}
    for k, v in pairs(val) do
      local kt = type(k)
      if (kt == "string" or kt == "number") and k ~= "_class" and k ~= "super" then
        local cv = _plainLuaCopy(v, d + 1)
        if cv ~= nil then out[k] = cv end
      end
    end
    return out
  end

  local function _extractPlainPayRow(rawRow)
    if type(rawRow) ~= "table" then return nil end
    local out = {}
    for _, nk in ipairs({ "id", "recharge_type", "consume_money", "Stall", "days", "vip_exp" }) do
      out[nk] = tonumber(rawRow[nk]) or rawRow[nk]
    end
    for _, rk in ipairs({ "base_reward", "first_reward", "general_reward", "daily_reward" }) do
      out[rk] = _plainLuaCopy(rawRow[rk], 0)
    end
    return out
  end

  -- Uses cjson.decode in full Axmol runtime with a compact safe fallback for standalone LuaJIT tests.
  local _ESC_MAP = { ['"'] = '"', ['\\'] = '\\', ['/'] = '/', n = '\n', r = '\r', t = '\t', b = '\b', f = '\f' }
  local function _jsonDecodeSafe(str)
    if type(str) ~= "string" or str == "" then return nil end
    local cj = rawget(_G, "cjson") or (type(package) == "table" and package.loaded and package.loaded.cjson) or rawget(_G, "json")
    if type(cj) == "table" and type(cj.decode) == "function" then
      local ok, decoded = pcall(cj.decode, str)
      if ok and decoded ~= nil then return decoded end
    end
    local pos, len, parseVal = 1, #str, nil
    local function ws() pos = select(2, string.find(str, "^[ \t\r\n]*", pos)) + 1 end
    local function pStr()
      pos = pos + 1
      local parts = {}
      while pos <= len do
        local c = string.sub(str, pos, pos); pos = pos + 1
        if c == '"' then return table.concat(parts) end
        if c == '\\' then local e = string.sub(str, pos, pos); pos = pos + 1; parts[#parts + 1] = _ESC_MAP[e] or e
        else parts[#parts + 1] = c end
      end
    end
    parseVal = function()
      ws()
      local c = string.sub(str, pos, pos)
      if c == '"' then return pStr()
      elseif c == "{" then
        pos = pos + 1; ws(); local o = {}
        if string.sub(str, pos, pos) == "}" then pos = pos + 1; return o end
        while pos <= len do
          ws(); if string.sub(str, pos, pos) ~= '"' then return o end
          local k = pStr(); ws(); if string.sub(str, pos, pos) ~= ":" then return o end
          pos = pos + 1; o[k] = parseVal(); ws()
          local sep = string.sub(str, pos, pos); pos = pos + 1
          if sep ~= "," then return o end
        end
        return o
      elseif c == "[" then
        pos = pos + 1; ws(); local a = {}
        if string.sub(str, pos, pos) == "]" then pos = pos + 1; return a end
        while pos <= len do
          a[#a + 1] = parseVal(); ws()
          local sep = string.sub(str, pos, pos); pos = pos + 1
          if sep ~= "," then return a end
        end
        return a
      elseif string.sub(str, pos, pos + 3) == "true" then pos = pos + 4; return true
      elseif string.sub(str, pos, pos + 4) == "false" then pos = pos + 5; return false
      elseif string.sub(str, pos, pos + 3) == "null" then pos = pos + 4; return nil end
      local sIdx, eIdx = string.find(str, "^[+-]?%d+%.?%d*[eE]?[+-]?%d*", pos)
      if sIdx then pos = eIdx + 1; return tonumber(string.sub(str, sIdx, eIdx)) end
    end
    local okP, out = pcall(parseVal)
    return okP and out or nil
  end

)LUA",
        R"LUA(
  local _inInstantBuyDispatch = false

  local function _dispatchInstantBuy(payId, payPrice, payType, productName, currencyName, productDesc, extraData)
    local buyType = tonumber(type(extraData) == "table" and extraData[1]) or 0
    local itemId = tonumber(type(extraData) == "table" and extraData[2]) or 0
    local gTbl = rawget(_G, "g")

    local isTM = (type(gTbl) == "table" and gTbl.isTM == true) or (rawget(_G, "IS_IN_TM") == true)
      or buyType == 23 or buyType == 26 or buyType == 27 or buyType == 31

    local net = type(gTbl) == "table" and ((isTM and type(gTbl.network_TM) == "table" and gTbl.network_TM)
      or (type(gTbl.network) == "table" and gTbl.network) or gTbl.network_TM) or nil
    if type(net) ~= "table" or type(net.sendMsg) ~= "function" then return false end

    local method = isTM and "tmPay.instantBuy" or "pay.instantBuy"
    local payRow, numPayId = nil, tonumber(payId)
    if numPayId ~= nil and type(gTbl) == "table" then
      local okRow, rawRow = pcall(function()
        for _, dmKey in ipairs({ "databaseManager", "databaseManager_TM" }) do
          local dm = gTbl[dmKey]
          if type(dm) == "table" and dm.payReader and type(dm.payReader.getRowById) == "function" then
            return dm.payReader:getRowById(numPayId)
          end
        end
      end)
      if okRow and type(rawRow) == "table" then payRow = _extractPlainPayRow(rawRow) end
    end

    local payload = {
      pay_id = numPayId or 0,
      pay_id_str = tostring(payId or ""),
      pay_price = tonumber(payPrice) or 0,
      pay_type = tostring(payType or "00"),
      product_name = tostring(productName or ""),
      extra_data = type(extraData) == "table" and _plainLuaCopy(extraData, 0) or extraData,
      buy_type = buyType,
      item_id = itemId,
      pay_row = payRow,
    }

    local function rpcCallback(ret)
      if type(ret) == "table" and ret.show_gain_popup == true and type(ret.reward) == "table" and #ret.reward > 0 then
        pcall(function()
          local gt = rawget(_G, "g")
          if type(gt) ~= "table" then return end
          local pConst = (isTM and type(gt.panelNameConst_TM) == "table" and gt.panelNameConst_TM) or gt.panelNameConst
          local panelName = (type(pConst) == "table" and pConst.gainItemListInfoPanel) or "gainItemListInfoPanel"
          local opened = false
          if type(gt.moduleManager) == "table" and type(gt.moduleManager.open) == "function" then
            local okOpen, resOpen = pcall(gt.moduleManager.open, panelName, ret.reward)
            opened = (okOpen and resOpen ~= false)
          end
          if not opened then
            local rList = (isTM and gt.rewardListInfoManager_TM) or gt.rewardListInfoManager
            if type(rList) == "table" and type(rList.showInfo) == "function" then
              pcall(rList.showInfo, rList, ret.reward)
            elseif type(gt.tipsManager) == "table" and type(gt.tipsManager.showTextTips) == "function" then
              pcall(gt.tipsManager.showTextTips, gt.tipsManager, tostring(ret.msg or "OK"))
            elseif type(gt.alertSuspend) == "table" and type(gt.alertSuspend.showAlert) == "function" then
              pcall(gt.alertSuspend.showAlert, gt.alertSuspend, tostring(ret.msg or "OK"))
            end
          end
        end)
      end
    end

    _inInstantBuyDispatch = true
    local okSend = pcall(net.sendMsg, net, method, rpcCallback, payload)
    _inInstantBuyDispatch = false
    return okSend
  end

  local _wrappedSdkGetPlFns, _wrappedSdkPayFns = _weakMap(), _weakMap()
  local _wrappedPlatformPayFns, _wrappedPlatformHostFns = _weakMap(), _weakMap()
)LUA",
        R"LUA(
  local _wrappedHttpSetUrlFns, _wrappedRestartFns, _wrappedReloadFns = _weakMap(), _weakMap(), _weakMap()

  local _DEAD_STAGING_DOMAINS = {
    "zing.vn", "zingplay.com", "vnggames.com", "gtarcade.com", "babeltime.com",
    "192.168.1.240", "10.0.0.240",
  }

  local function _isDeadStagingHostLua(host)
    if type(host) ~= "string" or host == "" then return false end
    local h = string.lower(host)
    for i = 1, #_DEAD_STAGING_DOMAINS do
      local dom = _DEAD_STAGING_DOMAINS[i]
      if h == dom or string.sub(h, -(#dom + 1)) == ("." .. dom) then return true end
    end
    return false
  end

  local function _defaultRelayOrigin()
    local gTbl = rawget(_G, "g")
    local orig = (type(gTbl) == "table" and type(gTbl.__cobaltRelayHttpOrigin) == "string" and gTbl.__cobaltRelayHttpOrigin ~= "")
      and gTbl.__cobaltRelayHttpOrigin or "http://127.0.0.1:8080"
    return (string.gsub(orig, "/+$", ""))
  end

  local function _rewriteDeadStagingUrl(url)
    if type(url) ~= "string" or url == "" then return url end
    local cHook = rawget(_G, "__gclient_rewrite_http_url")
    if type(cHook) == "function" then
      local ok, rewritten = pcall(cHook, url)
      if ok and type(rewritten) == "string" and rewritten ~= "" then return rewritten end
    end
    local scheme, auth, rest = string.match(url, "^([hH][tT][tT][pP][sS]?)://([^/%?#]+)(.*)$")
    if not scheme or not auth then return url end
    local hostOnly = string.gsub(string.gsub(auth, "^.*@", ""), ":%d+$", "")
    if not _isDeadStagingHostLua(hostOnly) then return url end
    return _defaultRelayOrigin() .. (rest or "")
  end

  local function _patchSDKUtilTable(sdkTbl)
    if type(sdkTbl) ~= "table" then return end
    _patchMethodOnce(sdkTbl, "getPL", _wrappedSdkGetPlFns, function(origGetPl)
      return function(...)
        local rawPl = nil
        if type(origGetPl) == "function" then
          local ok, res = pcall(origGetPl, ...)
          if ok then rawPl = res end
        else
          local plat = rawget(_G, "Platform")
          if type(plat) == "table" and type(plat.getPL) == "function" then
            local ok, res = pcall(plat.getPL, plat)
            if ok then rawPl = res end
          end
        end
        return _normalizeVngPlatform(rawPl)
      end
    end)

    _patchMethodOnce(sdkTbl, "pay", _wrappedSdkPayFns, function(origPay)
      return function(payId, payPrice, payType, productName, currencyName, productDesc, extraData)
        if _dispatchInstantBuy(payId, payPrice, payType, productName, currencyName, productDesc, extraData) then return end
        if type(origPay) == "function" then
          pcall(origPay, payId, payPrice, payType, productName, currencyName, productDesc, extraData)
        end
      end
    end)
  end

  local function _patchHttpReqClass(reqCls)
    if type(reqCls) ~= "table" or type(rawget(reqCls, "setUrl")) ~= "function" then return end
    _patchMethodOnce(reqCls, "setUrl", _wrappedHttpSetUrlFns, function(origSetUrl)
      return function(self, url, ...) return origSetUrl(self, _rewriteDeadStagingUrl(url), ...) end
    end)
  end

  local function _patchPlatformTable(platTbl)
    if type(platTbl) ~= "table" then return end
    for _, hostFnName in ipairs({ "getHost", "getLogHost" }) do
      if type(rawget(platTbl, hostFnName)) == "function" then
        _patchMethodOnce(platTbl, hostFnName, _wrappedPlatformHostFns, function(origHostFn)
          return function(...)
            local ok, res = pcall(origHostFn, ...)
            if not ok then return "http://127.0.0.1:8080" end
            if type(res) == "string" then
              if res == "" or res == "null" then return "http://127.0.0.1:8080" end
)LUA",
        R"LUA(
              return _rewriteDeadStagingUrl(res)
            end
            return res
          end
        end)
      end
    end

    _patchMethodOnce(platTbl, "pay", _wrappedPlatformPayFns, function(origPlatPay)
      return function(a1, a2, ...)
        local selfObj = (type(a1) == "table" or type(a1) == "userdata") and a1 or nil
        local jsonStr = selfObj and a2 or a1
        if not _inInstantBuyDispatch and type(jsonStr) == "string" and jsonStr ~= "" then
          local parsed = _jsonDecodeSafe(jsonStr)
          if type(parsed) == "table" then
            local pId = parsed.pay_id or parsed.ProductId or parsed.product_id or parsed.payId or parsed.productId
            local pPrice = parsed.pay_price or parsed.ProductPrice or parsed.product_price or parsed.price or parsed.payPrice
            local pType = parsed.pay_type or parsed.PayType or parsed.payType or "00"
            local pName = parsed.product_name or parsed.ProductName or parsed.productName or ""
            local cName = parsed.currency_name or parsed.CurrencyName or parsed.currencyName or "VND"
            local pDesc = parsed.product_desc or parsed.ProductDesc or parsed.productDesc or ""
            local ex = parsed.extra_data
            if ex == nil then ex = parsed.ExtraData end
            if ex == nil then ex = parsed.extraData end
            if ex == nil then ex = parsed.private_data end
            if type(ex) == "string" and ex ~= "" then
              local decEx = _jsonDecodeSafe(ex)
              if decEx ~= nil then
                ex = decEx
              elseif string.find(ex, "_", 1, true) then
                local parts = {}
                for tok in string.gmatch(ex, "[^_]+") do parts[#parts + 1] = tonumber(tok) or tok end
                if #parts > 0 then ex = parts end
              end
            end
            _dispatchInstantBuy(pId, pPrice, pType, pName, cName, pDesc, ex)
          end
        end
        if type(origPlatPay) == "function" then
          if selfObj ~= nil then return origPlatPay(selfObj, jsonStr, ...) end
          return origPlatPay(a1, a2, ...)
        end
      end
    end)
  end

  local function _prepareCleanRestartTeardown()
    local gTbl = rawget(_G, "g")
    if type(gTbl) == "table" then
      for _, netKey in ipairs({ "network", "network_TM" }) do
        local n = gTbl[netKey]
        if type(n) == "table" then
          if type(n._inFlightWatchdogs) == "table" then
            for cbKey, _ in pairs(n._inFlightWatchdogs) do _cancelInFlightWatchdog(n, cbKey) end
          end
          local c = n.mConn
          n.mConn = nil
          if c ~= nil and type(c.close) == "function" then pcall(c.close, c) end
        end
      end
    end
    local softRestartHook = rawget(_G, "__gclient_on_lua_soft_restart")
    if type(softRestartHook) == "function" then pcall(softRestartHook) end
  end

  local function _normModName(name)
    if type(name) ~= "string" then return "" end
    local s = string.gsub(string.gsub(name, "\\", "/"), "/", ".")
    return string.sub(s, 1, 8) == "scripts." and string.sub(s, 9) or s
  end

  local _sweepLoaded
  local function _wrapRestartFunction(fn)
    if type(fn) ~= "function" or _wrappedRestartFns[fn] then return fn end
    local wrappedRestart = function(...)
      _prepareCleanRestartTeardown()
      local r1, r2 = fn(...)
      if type(_sweepLoaded) == "function" then pcall(_sweepLoaded) end
      return r1, r2
    end
    _wrappedRestartFns[wrappedRestart] = fn
    return wrappedRestart
  end

  local function _syncRuntimeGlobals()
    local gTbl = rawget(_G, "g")
    if type(gTbl) == "table" then
)LUA",
        R"LUA(
      if type(gTbl.host) == "string" and gTbl.host ~= "" then gTbl.host = _rewriteDeadStagingUrl(gTbl.host) end
      for _, pair in ipairs({ { "network", true }, { "network_TM", false } }) do
        local n = gTbl[pair[1]]
        if type(n) == "table" and type(n.onBodyData) == "function" then _patchNetworkTarget(n, pair[2]) end
      end
      if type(gTbl.SDKUtil) == "table" then _patchSDKUtilTable(gTbl.SDKUtil) end
      for _, dmKey in ipairs({ "databaseManager", "databaseManager_TM" }) do
        if type(gTbl[dmKey]) == "table" and type(gTbl[dmKey].payReader) == "table" then
          _patchPayReaderTarget(gTbl[dmKey].payReader)
        end
      end
      for _, mdKey in ipairs({ "mainData", "mainData_TM" }) do
        if type(gTbl[mdKey]) == "table" and gTbl[mdKey].userdata ~= nil then
          _normalizeUserDataTarget(gTbl[mdKey].userdata)
        end
      end
    end

    local uTbl = rawget(_G, "utils")
    if type(uTbl) == "table" and type(uTbl.SDKUtil) == "table" then _patchSDKUtilTable(uTbl.SDKUtil) end

    if type(debug) == "table" and type(debug.getregistry) == "function" then
      local okReg, reg = pcall(debug.getregistry)
      if okReg and type(reg) == "table" then
        _patchHttpReqClass(reg["CCHttpRequest"])
        _patchHttpReqClass(reg["LuaHttpRequest"])
      end
    end
    _patchHttpReqClass(rawget(_G, "CCHttpRequest"))
    _patchHttpReqClass(rawget(_G, "LuaHttpRequest"))

    local plat = rawget(_G, "Platform")
    if type(plat) == "table" then
      _patchPlatformTable(plat)
      local mt = getmetatable(plat)
      if type(mt) == "table" and mt ~= plat then _patchPlatformTable(mt) end
      if type(plat.getInstance) == "function" then
        local okI, inst = pcall(plat.getInstance, plat)
        if okI and type(inst) == "table" and inst ~= plat then _patchPlatformTable(inst) end
      end
    elseif type(plat) == "userdata" and type(debug) == "table" and type(debug.getmetatable) == "function" then
      local mt = debug.getmetatable(plat)
      if type(mt) == "table" then _patchPlatformTable(mt) end
    end

    if type(rawget(_G, "reload")) == "function" then
      _patchMethodOnce(_G, "reload", _wrappedReloadFns, function(origReload)
        return function(...)
          local r1, r2 = origReload(...)
          if type(_sweepLoaded) == "function" then pcall(_sweepLoaded) end
          return r1, r2
        end
      end)
    end

    if type(rawget(_G, "restartGame")) == "function" then
      _G.restartGame = _wrapRestartFunction(_G.restartGame)
    end
    local appTbl = rawget(_G, "Application")
    if type(appTbl) == "table" and type(appTbl.restartGame) == "function" then
      appTbl.restartGame = _wrapRestartFunction(appTbl.restartGame)
    end
  end

  local function _inspectModule(modName, modVal)
    if type(modVal) == "table" then
      local norm = _normModName(modName)
      if norm == "system.Network" then
        _patchNetworkModule(modVal, true)
      elseif norm == "core.BindableData" then
        _patchBindableClass(modVal)
      elseif norm == "core.BaseProxy" or norm == "core.BaseProxy_TM" then
        _patchBaseProxyModule(modVal)
      elseif norm == "utils.SDKUtil" then
        _patchSDKUtilTable(modVal)
      elseif norm == "game.dbReader.PayReader" then
        _patchPayReaderTarget(modVal)
      elseif norm == "game.gamedata.UserData" or norm == "game.game_TM.gamedata_TM.UserData" then
        _patchUserDataModule(modVal)
      elseif norm == "system.Application" or norm == "Application" then
        if type(modVal.restartGame) == "function" then modVal.restartGame = _wrapRestartFunction(modVal.restartGame) end
)LUA",
        R"LUA(
      elseif string.find(norm, "Network$", 1) and norm ~= "system.NetworkUtil" then
        if type(rawget(modVal, "onBodyData")) == "function" and type(rawget(modVal, "sendMsg")) == "function" then
          _patchNetworkModule(modVal, false)
        end
      else
        local sup, depth = rawget(modVal, "super"), 0
        while type(sup) == "table" and depth < 8 do
          if rawget(sup, "_patchedGClientBindableResilience") or (type(sup.toString) == "function" and sup:toString() == "BindableData") then
            _patchBindableClass(modVal)
            break
          end
          sup, depth = rawget(sup, "super"), depth + 1
        end
      end
    end
    _syncRuntimeGlobals()
  end

  _sweepLoaded = function()
    if type(package) == "table" and type(package.loaded) == "table" then
      local bd = package.loaded["core.BindableData"] or package.loaded["core/BindableData"]
        or package.loaded["scripts/core/BindableData"] or package.loaded["scripts.core.BindableData"]
      if type(bd) == "table" then _patchBindableClass(bd) end
      for k, v in pairs(package.loaded) do
        if type(k) == "string" and type(v) == "table" then _inspectModule(k, v) end
      end
    end
    _syncRuntimeGlobals()
  end

  _G.__gclient_apply_net_resilience_sweep = _sweepLoaded
  _G.__gclient_rewrite_dead_staging_url = _rewriteDeadStagingUrl

  local origRequire = _G.require
  if type(origRequire) == "function" then
    _G.require = function(modName, ...)
      local res = origRequire(modName, ...)
      _inspectModule(modName, res)
      return res
    end
  end

  _sweepLoaded()
end
)LUA"
    };

    std::string fullScript;
    fullScript.reserve(49152);
    for (const char* chunk : kLuaChunks) {
        if (chunk != nullptr) fullScript.append(chunk);
    }

    const int savedTop = lua_gettop(L);
    if (luaL_loadbuffer(L, fullScript.data(), fullScript.size(), "@gclient_network_resilience") == 0 &&
        lua_pcall(L, 0, 0, 0) != 0) {
        const char* err = lua_tostring(L, -1);
        lua_getglobal(L, "CCLuaLog");
        if (lua_isfunction(L, -1)) {
            lua_pushfstring(L, "[NetResilience] Hook bootstrap error: %s", err ? err : "(null)");
            if (lua_pcall(L, 1, 0, 0) != 0) lua_pop(L, 1);
        } else {
            lua_pop(L, 1);
        }
    }
    lua_settop(L, savedTop);
}

} // namespace gclient::bindings
