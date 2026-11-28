#include "compat/Lua226CompatShim.h"
#include "diagnostics/CrashAndTelemetry.h"

extern "C" {
#include "lua.h"
#include "lauxlib.h"
}

#include <fstream>
#include <iterator>
#include <string>

namespace gclient::compat {

namespace {

// Split into <4 KB string literal chunks to stay strictly below MSVC C2026 (16,380-byte literal cap).
static const char* const kLua226CompatChunks[] = {
    R"LUA(
do
  ax   = ax or cc or {}
  cc   = ax
  axui = axui or ccui or {}
  ccui = axui
  ccs  = ccs or {}
  sp   = sp or {}

  string.gfind = string.gfind or string.gmatch
  math.mod     = math.mod or math.fmod
  unpack       = unpack or table.unpack

  local function _seq(tbl, startVal, names, keepExisting)
    local idx = startVal
    for k in names:gmatch("%S+") do
      if not keepExisting or tbl[k] == nil then tbl[k] = idx end
      idx = idx + 1
    end
  end

  ax.Handler = ax.Handler or {}
  _seq(ax.Handler, 0, [[
    NODE MENU_CLICKED CALLFUNC SCHEDULE TOUCHES KEYPAD ACCELEROMETER
    CONTROL_TOUCH_DOWN CONTROL_TOUCH_DRAG_INSIDE CONTROL_TOUCH_DRAG_OUTSIDE
    CONTROL_TOUCH_DRAG_ENTER CONTROL_TOUCH_DRAG_EXIT CONTROL_TOUCH_UP_INSIDE
    CONTROL_TOUCH_UP_OUTSIDE CONTROL_TOUCH_UP_CANCEL CONTROL_VALUE_CHANGED
    WEBSOCKET_OPEN WEBSOCKET_MESSAGE WEBSOCKET_CLOSE WEBSOCKET_ERROR GL_NODE_DRAW
    SCROLLVIEW_SCROLL SCROLLVIEW_ZOOM TABLECELL_TOUCHED TABLECELL_HIGHLIGHT
    TABLECELL_UNHIGHLIGHT TABLECELL_WILL_RECYCLE TABLECELL_SIZE_FOR_INDEX
    TABLECELL_AT_INDEX TABLEVIEW_NUMS_OF_CELLS HTTPREQUEST_STATE_CHANGE
    ASSETSMANAGER_PROGRESS ASSETSMANAGER_SUCCESS ASSETSMANAGER_ERROR
    STUDIO_EVENT_LISTENER ARMATURE_EVENT EVENT_ACC EVENT_CUSTIOM
    EVENT_KEYBOARD_PRESSED EVENT_KEYBOARD_RELEASED
    EVENT_TOUCH_BEGAN EVENT_TOUCH_MOVED EVENT_TOUCH_ENDED EVENT_TOUCH_CANCELLED
    EVENT_TOUCHES_BEGAN EVENT_TOUCHES_MOVED EVENT_TOUCHES_ENDED EVENT_TOUCHES_CANCELLED
    EVENT_MOUSE_DOWN EVENT_MOUSE_UP EVENT_MOUSE_MOVE EVENT_MOUSE_SCROLL
    EVENT_SPINE EVENT_PHYSICS_CONTACT_BEGIN EVENT_PHYSICS_CONTACT_PRESOLVE
    EVENT_PHYSICS_CONTACT_POSTSOLVE EVENT_PHYSICS_CONTACT_SEPARATE EVENT_FOCUS
  ]], true)
  _seq(ax.Handler, 64, "EVENT_SPINE_ANIMATION_START EVENT_SPINE_ANIMATION_END EVENT_SPINE_ANIMATION_COMPLETE EVENT_SPINE_ANIMATION_EVENT", true)

  function CCPoint(x, y)
    if type(x) == "table" then return { x = x.x or x[1] or 0, y = x.y or x[2] or 0 } end
    return { x = tonumber(x) or 0, y = tonumber(y) or 0 }
  end
  ccp, CCPointMake = CCPoint, CCPoint

  function CCSize(w, h)
    local rw = (type(w) == "table") and (w.width or w.x or w[1] or 0) or (tonumber(w) or 0)
    local rh = (type(w) == "table") and (w.height or w.y or w[2] or 0) or (tonumber(h) or 0)
    return { width = rw, height = rh, x = rw, y = rh }
  end
  CCSizeMake = CCSize

  function CCRect(x, y, w, h)
    if type(x) == "table" then
      return { x = x.x or 0, y = x.y or 0, width = x.width or 0, height = x.height or 0 }
    end
    return { x = tonumber(x) or 0, y = tonumber(y) or 0, width = tonumber(w) or 0, height = tonumber(h) or 0 }
  end
  CCRectMake = CCRect

  CCPointZero = { x = 0, y = 0 }
  CCSizeZero  = { width = 0, height = 0, x = 0, y = 0 }
  CCRectZero  = { x = 0, y = 0, width = 0, height = 0 }

  function ccc3(r, g, b) return { r = tonumber(r) or 0, g = tonumber(g) or 0, b = tonumber(b) or 0 } end
  function ccc4(r, g, b, a) return { r = tonumber(r) or 0, g = tonumber(g) or 0, b = tonumber(b) or 0, a = tonumber(a) or 255 } end
  function ccc4f(r, g, b, a) return { r = tonumber(r) or 0, g = tonumber(g) or 0, b = tonumber(b) or 0, a = tonumber(a) or 1 } end

  ccWHITE, ccYELLOW, ccBLUE   = ccc3(255,255,255), ccc3(255,255,0), ccc3(0,0,255)
  ccGREEN, ccRED, ccMAGENTA   = ccc3(0,255,0),     ccc3(255,0,0),   ccc3(255,0,255)
  ccBLACK, ccORANGE, ccGRAY   = ccc3(0,0,0),       ccc3(255,127,0), ccc3(166,166,166)

  function ccpAdd(a, b) return { x = a.x + b.x, y = a.y + b.y } end
  function ccpSub(a, b) return { x = a.x - b.x, y = a.y - b.y } end
  function ccpMult(v, s) return { x = v.x * s, y = v.y * s } end
  function ccpMidpoint(a, b) return { x = (a.x + b.x) * 0.5, y = (a.y + b.y) * 0.5 } end
  function ccpDot(a, b) return a.x * b.x + a.y * b.y end
  function ccpLengthSQ(v) return v.x * v.x + v.y * v.y end
  function ccpLength(v) return math.sqrt(v.x * v.x + v.y * v.y) end
  function ccpDistanceSQ(a, b) local dx, dy = a.x - b.x, a.y - b.y; return dx * dx + dy * dy end
  function ccpDistance(a, b) return math.sqrt(ccpDistanceSQ(a, b)) end
  function ccpNormalize(v)
    local l = ccpLength(v)
    return (l <= 1e-7) and { x = 0, y = 0 } or { x = v.x / l, y = v.y / l }
  end
  function CCRectContainsPoint(r, pt)
    return r ~= nil and pt ~= nil and pt.x >= r.x and pt.x <= (r.x + r.width) and pt.y >= r.y and pt.y <= (r.y + r.height)
  end
  function CCRectIntersectsRect(a, b)
    return a ~= nil and b ~= nil and not (a.x > b.x + b.width or a.x + a.width < b.x or a.y > b.y + b.height or a.y + a.height < b.y)
  end
)LUA",
    R"LUA(
  _seq(_G, 0, "kResolutionExactFit kResolutionNoBorder kResolutionShowAll kResolutionFixedHeight kResolutionFixedWidth kResolutionUnKnown")
  _seq(_G, 0, "kCCTextAlignmentLeft kCCTextAlignmentCenter kCCTextAlignmentRight")
  _seq(_G, 0, "kCCVerticalTextAlignmentTop kCCVerticalTextAlignmentCenter kCCVerticalTextAlignmentBottom")
  _seq(_G, 0, "kCCNodeOnEnter kCCNodeOnExit kCCNodeOnEnterTransitionDidFinish kCCNodeOnExitTransitionDidStart kCCNodeOnCleanup")
  _seq(_G, 0, "GL_ZERO GL_ONE")
  _seq(_G, 0x0300, "GL_SRC_COLOR GL_ONE_MINUS_SRC_COLOR GL_SRC_ALPHA GL_ONE_MINUS_SRC_ALPHA GL_DST_ALPHA GL_ONE_MINUS_DST_ALPHA GL_DST_COLOR GL_ONE_MINUS_DST_COLOR")
  _seq(_G, 0, "LAYOUT_COLOR_NONE LAYOUT_COLOR_SOLID LAYOUT_COLOR_GRADIENT")
  _seq(_G, 0, "LAYOUT_ABSOLUTE LAYOUT_LINEAR_VERTICAL LAYOUT_LINEAR_HORIZONTAL LAYOUT_RELATIVE")
  _seq(_G, -1, "BRIGHT_NONE BRIGHT_NORMAL BRIGHT_HIGHLIGHT")
  _seq(_G, 0, "UI_TEX_TYPE_LOCAL UI_TEX_TYPE_PLIST")
  _seq(_G, 0, "TOUCH_EVENT_BEGAN TOUCH_EVENT_MOVED TOUCH_EVENT_ENDED TOUCH_EVENT_CANCELED")
  _seq(_G, 0, "SIZE_ABSOLUTE SIZE_PERCENT")
  _seq(_G, 0, "POSITION_ABSOLUTE POSITION_PERCENT")
  _seq(_G, 0, "CHECKBOX_STATE_EVENT_SELECTED CHECKBOX_STATE_EVENT_UNSELECTED")
  _seq(_G, 0, "LoadingBarTypeLeft LoadingBarTypeRight")
  _seq(_G, 0, "SCROLLVIEW_DIR_NONE SCROLLVIEW_DIR_VERTICAL SCROLLVIEW_DIR_HORIZONTAL SCROLLVIEW_DIR_BOTH")
  _seq(_G, 0, "LISTVIEW_GRAVITY_LEFT LISTVIEW_GRAVITY_RIGHT LISTVIEW_GRAVITY_CENTER_HORIZONTAL LISTVIEW_GRAVITY_TOP LISTVIEW_GRAVITY_BOTTOM LISTVIEW_GRAVITY_CENTER_VERTICAL")
  _seq(_G, 0, "TEXTFIELD_EVENT_ATTACH_WITH_IME TEXTFIELD_EVENT_DETACH_WITH_IME TEXTFIELD_EVENT_INSERT_TEXT TEXTFIELD_EVENT_DELETE_BACKWARD")

  kCCTexture2DPixelFormat_RGBA8888, kCCTexture2DPixelFormat_RGB888 = 2, 3
  kCCTexture2DPixelFormat_RGB565,   kCCTexture2DPixelFormat_A8     = 4, 5
  kCCTexture2DPixelFormat_RGBA4444, kCCTexture2DPixelFormat_RGB5A1 = 7, 8
  kCCMenuHandlerPriority = -128

  tolua = tolua or {}
  local _orig_tolua_cast, _orig_tolua_isnull = tolua.cast, tolua.isnull
  local _toluaTypeMap = {
    CCNodeRGBA = "ax.Node", CCLayerRGBA = "ax.Layer", CCTMXTiledMap = "ax.TMXTiledMap",
    CCLabelTTF = "ax.Label", CCLabelBMFont = "ax.Label",
    CCScale9Sprite = "axui.Scale9Sprite", CCEditBox = "axui.EditBox",
    TouchGroup = "TouchGroup", UILayer = "TouchGroup", RichText = "axui.RichText",
    Panel = "axui.Layout", TextButton = "axui.Button", DragPanel = "axui.ScrollView",
    Label = "axui.Text", UILabel = "axui.Text", Text = "axui.Text", TextArea = "axui.Text",
    LabelAtlas = "axui.TextAtlas", UILabelAtlas = "axui.TextAtlas", TextAtlas = "axui.TextAtlas",
    LabelBMFont = "axui.TextBMFont", UILabelBMFont = "axui.TextBMFont", TextBMFont = "axui.TextBMFont",
    CCArmature = "ccs.Armature", CCArmatureAnimation = "ccs.ArmatureAnimation",
    CCBone = "ccs.Bone", CCSkin = "ccs.Skin",
  }

  for n in ([[
    Object Node Scene Layer LayerColor LayerGradient Menu MenuItem MenuItemImage
    MenuItemSprite MenuItemLabel Sprite SpriteBatchNode SpriteFrame SpriteFrameCache
    Texture2D TextureCache Director Scheduler FileUtils UserDefault Application
    RenderTexture ClippingNode DrawNode ProgressTimer ParticleSystemQuad LabelAtlas
    ScrollView TableView TableViewCell ControlButton
  ]]):gmatch("%S+") do
    _toluaTypeMap["CC" .. n] = "ax." .. n
    _G["CC" .. n] = ax[n]
  end

  for n in ([[
    MenuItemFont MenuItemToggle MotionStreak Animation AnimationCache Animate
    Action FiniteTimeAction ActionInterval Speed Follow Repeat RepeatForever DelayTime
    CallFunc MoveTo MoveBy ScaleTo ScaleBy RotateTo RotateBy SkewTo SkewBy JumpTo JumpBy
    BezierTo BezierBy Blink FadeIn FadeOut FadeTo TintTo TintBy Show Hide Place RemoveSelf
    ToggleVisibility OrbitCamera ProgressTo ProgressFromTo EaseIn EaseOut EaseInOut
    EaseSineIn EaseSineOut EaseSineInOut EaseBackIn EaseBackOut EaseBackInOut
    EaseBounceIn EaseBounceOut EaseBounceInOut EaseElasticIn EaseElasticOut EaseElasticInOut
    EaseExponentialIn EaseExponentialOut EaseExponentialInOut
  ]]):gmatch("%S+") do
    _G["CC" .. n] = ax[n]
  end

  CCNodeRGBA, CCLayerRGBA, CCTMXTiledMap = ax.Node, ax.Layer, ax.TMXTiledMap
  CCLabelTTF, CCCallFuncN = ax.Label, ax.CallFunc
  CCScale9Sprite, CCEditBox = axui.Scale9Sprite, axui.EditBox

  for n in ("Widget Layout Button CheckBox ImageView LoadingBar Slider TextField ScrollView ListView PageView"):gmatch("%S+") do
    local t = "axui." .. n
    _toluaTypeMap[n], _toluaTypeMap["UI" .. n] = t, t
    _G[n], _G["UI" .. n] = axui[n], axui[n]
  end
  for n in ("RichText RichElement RichElementText RichElementImage RichElementCustomNode RichElementNewLine"):gmatch("%S+") do
    _toluaTypeMap[n] = "axui." .. n
    if axui[n] and _G[n] == nil then _G[n] = axui[n] end
  end
  Panel, TextButton, UIHelper = axui.Layout, axui.Button, axui.Helper
  Label, UILabel = axui.Text, axui.Text
  LabelAtlas, UILabelAtlas = axui.TextAtlas, axui.TextAtlas
  LabelBMFont, UILabelBMFont = axui.TextBMFont, axui.TextBMFont
  LinearLayoutParameter, RelativeLayoutParameter = axui.LinearLayoutParameter, axui.RelativeLayoutParameter
  Margin = function(l, t, r, b) return { left = l or 0, top = t or 0, right = r or 0, bottom = b or 0 } end

  GUIReader, SceneReader = ccs.GUIReader, ccs.SceneReader
  ActionManager, ActionManagerEx = ccs.ActionManagerEx, ccs.ActionManagerEx
  CCArmature, CCArmatureDataManager, CCArmatureAnimation = ccs.Armature, ccs.ArmatureDataManager, ccs.ArmatureAnimation
  CCBone, CCSkin = ccs.Bone, ccs.Skin
)LUA",
    R"LUA(
  tolua.cast = function(obj, typeName)
    if obj == nil then return nil end
    local mapped = _toluaTypeMap[typeName] or typeName
    if _orig_tolua_cast and type(obj) == "userdata" then
      local casted = _orig_tolua_cast(obj, mapped)
      if casted ~= nil then return casted end
      if mapped ~= typeName then
        casted = _orig_tolua_cast(obj, typeName)
        if casted ~= nil then return casted end
      end
    end
    return obj
  end

  tolua.isnull = function(obj)
    if obj == nil then return true end
    if _orig_tolua_isnull and type(obj) == "userdata" then return _orig_tolua_isnull(obj) end
    return false
  end

  if not tolua.getpeer then
    local _peers = setmetatable({}, { __mode = "k" })
    tolua.setpeer = function(u, t) _peers[u] = t end
    tolua.getpeer = function(u) return _peers[u] end
  end

  if ax.Label then
    CCLabelBMFont = setmetatable({
      create = function(cls, str, fntFile, width, hAlign, imageOffset)
        if ax.Label.createWithBMFont then
          return ax.Label:createWithBMFont(tostring(fntFile or ""), tostring(str or ""), hAlign or 0, tonumber(width) or 0, imageOffset or CCPointZero)
        end
        return ax.Label:create()
      end,
    }, { __index = ax.Label })
  end

  do
    local function _eachChild(node, fn)
      local list = (type(node.getChildren) == "function" and (node:getChildren() or {}))
                or (type(node) == "table" and type(node._children) == "table" and node._children)
                or nil
      if not list then return nil end
      for _, ch in ipairs(list) do
        local res = fn(ch)
        if res ~= nil then return res end
      end
      return nil
    end

    local function _seekWidget(node, key, getterName, rawField, ownSeek, helperSeek)
      if node == nil or key == nil or key == "" then return nil end
      if type(node[getterName]) == "function" and node[getterName](node) == key then return node end
      if type(node) == "table" and rawget(node, rawField) == key then return node end
      if type(node[ownSeek]) == "function" then
        local hit = node[ownSeek](node, key)
        if hit ~= nil then return hit end
      elseif axui.Helper and type(axui.Helper[helperSeek]) == "function" and type(node) == "userdata" then
        local hit = axui.Helper[helperSeek](axui.Helper, node, key)
        if hit ~= nil then return hit end
      end
      return _eachChild(node, function(ch)
        return _seekWidget(ch, key, getterName, rawField, ownSeek, helperSeek)
      end)
    end

    local function _resetTouchHighlight(node)
      if node == nil then return end
      if type(node.setHighlighted) == "function" then pcall(node.setHighlighted, node, false)
      elseif type(node) == "table" and rawget(node, "_highlighted") ~= nil then node._highlighted = false end
      _eachChild(node, function(ch) _resetTouchHighlight(ch) end)
    end

    local _existingTG = rawget(_G, "TouchGroup") or axui.TouchGroup or ccs.TouchGroup
    if type(_existingTG) == "table" and type(_existingTG.create) == "function" then
      local _reg = (type(debug) == "table" and type(debug.getregistry) == "function") and debug.getregistry() or nil
      local _tgMt = (_reg and _reg["TouchGroup"]) or _existingTG
      _existingTG.clearTouchStat = _existingTG.clearTouchStat or function(self)
        if self ~= nil then
          _resetTouchHighlight((type(self.getRootWidget) == "function" and self:getRootWidget()) or self)
        end
      end
      if type(_tgMt) == "table" then
        _tgMt.clearTouchStat = _tgMt.clearTouchStat or _existingTG.clearTouchStat
        _tgMt.getRootWidget  = _tgMt.getRootWidget or function(self) return self end
      end
      TouchGroup = _existingTG
    else
      local _tgState = setmetatable({}, { __mode = "k" })
      local _Proto = {}
      local _base = (type(ax.Layer) == "table" and ax.Layer) or (type(ax.Node) == "table" and ax.Node) or nil
      if _base then setmetatable(_Proto, { __index = _base }) end

      local function _data(self)
        local d = _tgState[self]
        if not d then
          local rw = (axui.Widget and type(axui.Widget.create) == "function") and axui.Widget:create() or { _children = {} }
          if type(rw) == "userdata" and type(rw.setTouchEnabled) == "function" then pcall(rw.setTouchEnabled, rw, false) end
          d = { widgets = {}, rootWidget = rw, priority = 0 }
          _tgState[self] = d
        end
        return d
      end
      function _Proto:addWidget(w)
        if w == nil then return end
        local d = _data(self); d.widgets[#d.widgets + 1] = w
        if type(self.addChild) == "function" then pcall(self.addChild, self, w)
        elseif type(d.rootWidget) == "table" and type(d.rootWidget._children) == "table" then
          d.rootWidget._children[#d.rootWidget._children + 1] = w
        end
      end
      function _Proto:removeWidget(w, cleanup)
        if w == nil then return end
        local d = _data(self)
        for i = #d.widgets, 1, -1 do if d.widgets[i] == w then table.remove(d.widgets, i) end end
        if type(self.removeChild) == "function" then pcall(self.removeChild, self, w, cleanup ~= false)
        elseif type(w.removeFromParent) == "function" then pcall(w.removeFromParent, w) end
      end
      function _Proto:getWidgetByName(name)
        if name == nil or name == "" then return nil end
        for _, w in ipairs(_data(self).widgets) do
          local hit = _seekWidget(w, name, "getName", "_name", "getWidgetByName", "seekWidgetByName")
          if hit ~= nil then return hit end
        end
        return nil
      end
      function _Proto:getWidgetByTag(tag)
        local numTag = tonumber(tag); if numTag == nil then return nil end
        for _, w in ipairs(_data(self).widgets) do
          local hit = _seekWidget(w, numTag, "getTag", "_tag", "getWidgetByTag", "seekWidgetByTag")
          if hit ~= nil then return hit end
        end
        return nil
      end
      function _Proto:getRootWidget() return _data(self).rootWidget end
      function _Proto:clear()
        local d = _data(self)
        for i = #d.widgets, 1, -1 do
          local w = d.widgets[i]; d.widgets[i] = nil
          if type(self.removeChild) == "function" then pcall(self.removeChild, self, w, true)
          elseif type(w) == "userdata" and type(w.removeFromParent) == "function" then pcall(w.removeFromParent, w) end
        end
      end
      function _Proto:clearTouchStat()
        for _, w in ipairs(_data(self).widgets) do _resetTouchHighlight(w) end
      end
      function _Proto:setTouchPriority(p) _data(self).priority = tonumber(p) or 0 end
      function _Proto:getTouchPriority() return _data(self).priority end
      function _Proto:create()
        if type(ax.Layer) == "table" and type(ax.Layer.create) == "function" then
          local ud = ax.Layer:create()
          if ud ~= nil then
            if type(ud) == "userdata" and tolua.setpeer then
              tolua.setpeer(ud, setmetatable({}, { __index = _Proto })); _data(ud); return ud
            elseif type(ud) == "table" then
              setmetatable(ud, { __index = _Proto }); _data(ud); return ud
            end
          end
        end
        local inst = setmetatable({ _children = {} }, { __index = _Proto }); _data(inst); return inst
      end
      TouchGroup = _Proto
    end
    _G.TouchGroup, _G.UILayer = TouchGroup, TouchGroup
    axui.TouchGroup, axui.UILayer = TouchGroup, TouchGroup
    ccs.TouchGroup, ccs.UILayer = TouchGroup, TouchGroup
  end
)LUA",
    R"LUA(
  local function _unpackActionArgs(first, ...)
    if first ~= nil and select("#", ...) == 0 then
      if type(first) == "userdata" and type(first.count) == "function" and type(first.objectAtIndex) == "function" then
        local list = {}
        for i = 0, first:count() - 1 do list[#list + 1] = first:objectAtIndex(i) end
        return unpack(list)
      elseif type(first) == "table" and first[1] ~= nil then
        return unpack(first)
      end
    end
    return first, ...
  end

  local function _wrapMultiAction(axCls)
    if not axCls then return nil end
    local origCreate = axCls.create
    return setmetatable({
      create = function(cls, ...) return origCreate(axCls, _unpackActionArgs(...)) end,
      createWithTwoActions = function(cls, a1, a2) return origCreate(axCls, a1, a2) end,
    }, { __index = axCls })
  end
  CCSequence = _wrapMultiAction(ax.Sequence) or CCSequence
  CCSpawn    = _wrapMultiAction(ax.Spawn) or CCSpawn

  if ax.CallFunc then
    CCCallFuncND = {
      create = function(cls, fn, data)
        return ax.CallFunc:create(function(sender) if fn then fn(sender, data) end end)
      end,
    }
  end

  if ax.Director then
    ax.Director.sharedDirector  = ax.Director.sharedDirector or function() return ax.Director:getInstance() end
    ax.Director.getOpenGLView   = ax.Director.getOpenGLView or function(self) return self:getRenderView() end
    ax.Director.setDisplayStats = ax.Director.setDisplayStats or ax.Director.setStatsDisplay
  end
  CCEGLView = { sharedOpenGLView = function() return ax.Director:getInstance():getRenderView() end }

  if not rawget(_G, "CCLuaEngine") then
    local _eng = {}
    function _eng:defaultEngine() return _eng end
    function _eng:getInstance() return _eng end
    function _eng:executeString(code)
      if type(code) ~= "string" then return 1 end
      local fn, err = loadstring(code)
      if not fn then
        if type(_G.__GCLIENT_LOG_ERR__) == "function" then _G.__GCLIENT_LOG_ERR__(tostring(err)) end
        return 1
      end
      return xpcall(fn, rawget(_G, "__G__TRACKBACK__") or debug.traceback) and 0 or 1
    end
    function _eng:executeScriptFile(filename)
      if type(filename) ~= "string" or filename == "" then return 1 end
      return xpcall(function() return dofile(filename) end, rawget(_G, "__G__TRACKBACK__") or debug.traceback) and 0 or 1
    end
    function _eng:reload(mod)
      if type(mod) ~= "string" or mod == "" then return 0 end
      local key = mod:gsub("%.lua$", "")
      package.loaded[key], package.loaded[key:gsub("/", ".")], package.loaded[key:gsub("%.", "/")] = nil, nil, nil
      return pcall(require, key) and 1 or 0
    end
    _G.CCLuaEngine = _eng
  end

  if ax.TextureCache then
    ax.TextureCache.sharedTextureCache = ax.TextureCache.sharedTextureCache or function() return ax.Director:getInstance():getTextureCache() end
    ax.TextureCache.dumpCachedTextureInfo = ax.TextureCache.dumpCachedTextureInfo or function(self)
      if self.getCachedTextureInfo then print(self:getCachedTextureInfo()) end
    end
    ax.TextureCache.textureForKey = ax.TextureCache.textureForKey or ax.TextureCache.getTextureForKey
  end

  local function _bindSingleton(cls, sharedFn, purgeFn, aliasDst, aliasSrc)
    if not cls then return end
    if sharedFn then cls[sharedFn] = cls[sharedFn] or function() return cls:getInstance() end end
    if purgeFn  then cls[purgeFn]  = cls[purgeFn]  or function() return cls:destroyInstance() end end
    if aliasDst and aliasSrc then cls[aliasDst] = cls[aliasDst] or cls[aliasSrc] end
  end
  _bindSingleton(ax.SpriteFrameCache,    "sharedSpriteFrameCache",    "purgeSharedSpriteFrameCache", "spriteFrameByName", "getSpriteFrameByName")
  _bindSingleton(ax.FileUtils,           "sharedFileUtils")
  _bindSingleton(ax.UserDefault,         "sharedUserDefault")
  _bindSingleton(ax.Application,         "sharedApplication")
  _bindSingleton(ax.AnimationCache,      "sharedAnimationCache",      "purgeSharedAnimationCache",   "animationByName",   "getAnimation")
  _bindSingleton(ccs.GUIReader,          "shareReader",               "purgeGUIReader")
  _bindSingleton(ccs.SceneReader,        "sharedSceneReader",         "purge")
  _bindSingleton(ccs.ActionManagerEx,    "shareManager",              "purgeActionManager")
  _bindSingleton(ccs.ArmatureDataManager,"sharedArmatureDataManager", "purge")

  do
    local _obs, _nc = {}, {}
    local function _prune(list, target)
      local kept = {}
      for _, e in ipairs(list) do if e.target ~= target then kept[#kept + 1] = e end end
      return (#kept > 0) and kept or nil
    end
    function _nc:sharedNotificationCenter() return _nc end
    function _nc:purgeNotificationCenter() _obs = {} end
    function _nc:unregisterAllScriptObservers(target)
      if target == nil then _obs = {}; return end
      for k, list in pairs(_obs) do _obs[k] = _prune(list, target) end
    end
    function _nc:registerScriptObserver(target, handler, name)
      if not name or not handler then return end
      _obs[name] = _obs[name] or {}
      _obs[name][#_obs[name] + 1] = { target = target, handler = handler }
    end
    function _nc:unregisterScriptObserver(target, name)
      if not name or not _obs[name] then return end
      _obs[name] = (target ~= nil) and _prune(_obs[name], target) or nil
    end
    function _nc:postNotification(name, obj)
      local list = name and _obs[name]
      if not list then return end
      local snap = {}
      for i = 1, #list do snap[i] = list[i] end
      for _, e in ipairs(snap) do if type(e.handler) == "function" then e.handler(name, obj) end end
    end
    CCNotificationCenter = _nc
  end
)LUA",
    R"LUA(
  if ax.Node then
    ax.Node.setZOrder              = ax.Node.setZOrder or ax.Node.setLocalZOrder
    ax.Node.getZOrder              = ax.Node.getZOrder or ax.Node.getLocalZOrder
    ax.Node.setVertexZ             = ax.Node.setVertexZ or ax.Node.setPositionZ
    ax.Node.getVertexZ             = ax.Node.getVertexZ or ax.Node.getPositionZ
    ax.Node.boundingBox            = ax.Node.boundingBox or ax.Node.getBoundingBox
    ax.Node.numberOfRunningActions = ax.Node.numberOfRunningActions or ax.Node.getNumberOfRunningActions
    ax.Node.removeFromParentAndCleanup   = ax.Node.removeFromParentAndCleanup or function(self) return self:removeFromParent() end
    ax.Node.removeAllChildrenWithCleanup = ax.Node.removeAllChildrenWithCleanup or function(self) return self:removeAllChildren() end
    ax.Node.pauseSchedulerAndActions     = ax.Node.pauseSchedulerAndActions or ax.Node.pause
    ax.Node.resumeSchedulerAndActions    = ax.Node.resumeSchedulerAndActions or ax.Node.resume
    ax.Node.setShaderWithVertexShaderByteArray = ax.Node.setShaderWithVertexShaderByteArray or function(self) return self end
    ax.Node.setSize = ax.Node.setSize or function(self, a, b) if b ~= nil then return self:setContentSize(a, b) end return self:setContentSize(a) end
    ax.Node.getSize = ax.Node.getSize or function(self) return self:getContentSize() end
  end

  if ax.Layer then
    local _layerState = setmetatable({}, { __mode = "k" })
    local function _st(self)
      local s = _layerState[self]
      if not s then
        s = { enabled = false, priority = 0, swallows = false, isMulti = false, handler = nil, listener = nil }
        _layerState[self] = s
      end
      return s
    end
    local function _rebuild(self)
      local s = _st(self)
      if not ax.Director or type(ax.Director.getInstance) ~= "function" then return end
      local dir = ax.Director:getInstance()
      local disp = dir and type(dir.getEventDispatcher) == "function" and dir:getEventDispatcher()
      if not disp then return end
      if s.listener then disp:removeEventListener(s.listener); s.listener = nil end
      if not s.enabled or type(s.handler) ~= "function" then return end

      if s.isMulti and ax.EventListenerTouchAllAtOnce then
        local l = ax.EventListenerTouchAllAtOnce:create()
        local function pack(touches)
          local tb = {}
          for _, t in ipairs(touches or {}) do
            local loc = t:getLocation()
            tb[#tb + 1], tb[#tb + 1], tb[#tb + 1] = loc.x, loc.y, t:getId()
          end
          return tb
        end
        for _, p in ipairs({
          { "began", ax.Handler.EVENT_TOUCHES_BEGAN }, { "moved", ax.Handler.EVENT_TOUCHES_MOVED },
          { "ended", ax.Handler.EVENT_TOUCHES_ENDED }, { "cancelled", ax.Handler.EVENT_TOUCHES_CANCELLED },
        }) do
          l:registerScriptHandler(function(touches) s.handler(p[1], pack(touches)) end, p[2])
        end
        disp:addEventListenerWithSceneGraphPriority(l, self); s.listener = l
      elseif ax.EventListenerTouchOneByOne then
        local l = ax.EventListenerTouchOneByOne:create()
        l:setSwallowTouches(s.swallows and true or false)
        l:registerScriptHandler(function(touch)
          local loc = touch:getLocation()
          return s.handler("began", loc.x, loc.y) ~= false
        end, ax.Handler.EVENT_TOUCH_BEGAN)
        for _, p in ipairs({
          { "moved", ax.Handler.EVENT_TOUCH_MOVED },
          { "ended", ax.Handler.EVENT_TOUCH_ENDED },
          { "cancelled", ax.Handler.EVENT_TOUCH_CANCELLED },
        }) do
          l:registerScriptHandler(function(touch)
            local loc = touch:getLocation(); s.handler(p[1], loc.x, loc.y)
          end, p[2])
        end
        disp:addEventListenerWithSceneGraphPriority(l, self); s.listener = l
      end
    end

    kCCTouchesAllAtOnce = kCCTouchesAllAtOnce or 0
    kCCTouchesOneByOne  = kCCTouchesOneByOne or 1
    ax.Layer.setTouchEnabled = ax.Layer.setTouchEnabled or function(self, en) _st(self).enabled = en and true or false; _rebuild(self) end
    ax.Layer.isTouchEnabled  = ax.Layer.isTouchEnabled or function(self) return _st(self).enabled end
    ax.Layer.setTouchMode    = ax.Layer.setTouchMode or function(self, m)
      local s = _st(self); s.mode = tonumber(m) or 1
      local wantMulti = (s.mode == 0)
      if s.isMulti ~= wantMulti then s.isMulti = wantMulti; _rebuild(self) end
    end
    ax.Layer.getTouchMode    = ax.Layer.getTouchMode or function(self) return _st(self).mode or 1 end
    ax.Layer.setSwallowsTouches = ax.Layer.setSwallowsTouches or function(self, b) _st(self).swallows = b and true or false; _rebuild(self) end
    ax.Layer.isSwallowsTouches  = ax.Layer.isSwallowsTouches or function(self) return _st(self).swallows end
    ax.Layer.setTouchPriority = ax.Layer.setTouchPriority or function(self, p) _st(self).priority = tonumber(p) or 0 end
    ax.Layer.getTouchPriority = ax.Layer.getTouchPriority or function(self) return _st(self).priority end
    ax.Layer.registerScriptTouchHandler = ax.Layer.registerScriptTouchHandler or function(self, fn, isMulti, prio, swallows)
      local s = _st(self)
      s.handler, s.isMulti, s.priority, s.swallows = fn, isMulti and true or false, tonumber(prio) or s.priority, swallows and true or false
      s.mode = s.isMulti and 0 or 1
      _rebuild(self)
    end
    ax.Layer.unregisterScriptTouchHandler = ax.Layer.unregisterScriptTouchHandler or function(self)
      _st(self).handler = nil; _rebuild(self)
    end
    ax.Layer.setKeypadEnabled = ax.Layer.setKeypadEnabled or function(self, en) _st(self).keypad = en and true or false end
    ax.Layer.isKeypadEnabled  = ax.Layer.isKeypadEnabled or function(self) return _st(self).keypad or false end
    ax.Layer.registerScriptKeypadHandler = ax.Layer.registerScriptKeypadHandler or function(self, fn) _st(self).keypadHandler = fn end
    ax.Layer.unregisterScriptKeypadHandler = ax.Layer.unregisterScriptKeypadHandler or function(self) _st(self).keypadHandler = nil end
  end

  if ax.ScrollView then
    ax.ScrollView.setMinAndMaxScale = ax.ScrollView.setMinAndMaxScale or function(self, minS, maxS)
      if minS and self.setMinScale then self:setMinScale(minS) end
      if maxS and self.setMaxScale then self:setMaxScale(maxS) end
    end
    ax.ScrollView.setTouchPriority = ax.ScrollView.setTouchPriority or function() end
  end

  do
    local function _enableStroke(self, c3, size)
      if self and self.enableOutline then
        local c = type(c3) == "table" and ccc4(c3.r or 0, c3.g or 0, c3.b or 0, c3.a or 255) or ccc4(0, 0, 0, 255)
        return self:enableOutline(c, tonumber(size) or 1)
      end
    end
    local function _disableStroke(self)
      if self and self.disableEffect then return self:disableEffect() end
    end
    for _, _lbl in ipairs({ ax.Label, axui.Text, axui.TextBMFont }) do
      if _lbl then
        _lbl.enableStroke  = _lbl.enableStroke  or _enableStroke
        _lbl.disableStroke = _lbl.disableStroke or _disableStroke
        if _lbl.enableShadow then
          local _origSh = _lbl.enableShadow
          _lbl.enableShadow = function(self, a1, a2, a3)
            if type(a1) == "table" and a1.r == nil and (a1.width ~= nil or a1.x ~= nil) then
              local op = tonumber(a2) or 255
              if op > 0 and op <= 1 then op = math.floor(op * 255 + 0.5) end
              local off = { x = tonumber(a1.width or a1.x) or 2, y = tonumber(a1.height or a1.y) or -2 }
              return _origSh(self, ccc4(0, 0, 0, op), off, math.floor(tonumber(a3) or 0))
            end
            return _origSh(self, a1, a2, a3)
          end
        end
      end
    end
    if axui.Button then
      axui.Button.enableTitleStroke = axui.Button.enableTitleStroke or function(self, c3, size)
        local r = self.getTitleRenderer and self:getTitleRenderer()
        if r then return _enableStroke(r, c3, size) end
      end
      axui.Button.disableTitleStroke = axui.Button.disableTitleStroke or function(self)
        local r = self.getTitleRenderer and self:getTitleRenderer()
        if r then return _disableStroke(r) end
      end
    end
  end
)LUA",
    R"LUA(
  if ax.Label then
    local _origCreate = ax.Label.create
    ax.Label.create = function(cls, text, fontName, fontSize, dims, hAlign, vAlign)
      if text == nil then return _origCreate(cls) end
      local fn, fs = tostring(fontName or "Arial"), tonumber(fontSize) or 20
      if fn:sub(-4):lower() == ".fnt" and ax.Label.createWithBMFont then
        return ax.Label:createWithBMFont(fn, tostring(text), hAlign or 0, tonumber(fontSize) or 0, CCPointZero)
      end
      if ax.FileUtils and ax.FileUtils:getInstance():isFileExist(fn) and ax.Label.createWithTTF then
        return ax.Label:createWithTTF(tostring(text), fn, fs, dims or CCSizeZero, hAlign or 0, vAlign or 0)
      end
      return ax.Label:createWithSystemFont(tostring(text), fn, fs, dims or CCSizeZero, hAlign or 0, vAlign or 0)
    end
  end

  local function _wrapTargetCb(origFn)
    return function(self, a1, a2)
      if not origFn then return end
      if type(a1) == "function" and a2 == nil then return origFn(self, a1)
      elseif type(a2) == "function" then
        return origFn(self, function(sender, ev) a2(a1, sender, ev) end)
      end
    end
  end

  if axui.Widget then
    axui.Widget.setSize         = function(self, a, b) if b ~= nil then return self:setContentSize(a, b) end return self:setContentSize(a) end
    axui.Widget.getSize         = function(self) return self:getContentSize() end
    axui.Widget.getWidgetByName = axui.Widget.getWidgetByName or function(self, n) return axui.Helper:seekWidgetByName(self, n) end
    axui.Widget.getWidgetByTag  = axui.Widget.getWidgetByTag or function(self, t) return axui.Helper:seekWidgetByTag(self, t) end
    if axui.Widget.addTouchEventListener then
      axui.Widget.addTouchEventListener = _wrapTargetCb(axui.Widget.addTouchEventListener)
    end
  end

  for _, name in ipairs({ "Text", "TextBMFont", "TextField" }) do
    local cls = axui[name]
    if cls then
      cls.setText        = cls.setText or cls.setString
      cls.getStringValue = cls.getStringValue or cls.getString
    end
  end
  if axui.TextAtlas then
    axui.TextAtlas.setStringValue = axui.TextAtlas.setStringValue or axui.TextAtlas.setString
    axui.TextAtlas.getStringValue = axui.TextAtlas.getStringValue or axui.TextAtlas.getString
  end
  if axui.CheckBox then
    axui.CheckBox.addEventListenerCheckBox = _wrapTargetCb(axui.CheckBox.addEventListener or axui.CheckBox.addEventListenerCheckBox)
  end
end
)LUA",
};

static const char* const kExternalShimLoaderChunk = R"LUA(
do
  local candidates = {
    "compat_axmol_runtime.lua",
    "scripts/compat_axmol_runtime.lua",
    "bootstrap/compat_axmol_runtime.lua",
    "Resources/scripts/compat_axmol_runtime.lua",
    "lua_scripts/compat_axmol_runtime.lua",
  }
  if ax and ax.FileUtils and type(ax.FileUtils.getInstance) == "function" then
    local okFu, fu = pcall(ax.FileUtils.getInstance, ax.FileUtils)
    if okFu and fu and type(fu.isFileExist) == "function" and type(fu.getStringFromFile) == "function" then
      for _, p in ipairs(candidates) do
        local okEx, ex = pcall(fu.isFileExist, fu, p)
        if okEx and ex then
          local okStr, src = pcall(fu.getStringFromFile, fu, p)
          if okStr and type(src) == "string" and #src > 0 then
            local chunk = (loadstring or load)(src, "@" .. p)
            if chunk then
              local okRun, runErr = pcall(chunk)
              if okRun then
                if type(package) == "table" and type(package.loaded) == "table" then
                  package.loaded["compat_axmol_runtime"] = true
                end
                return true
              elseif type(__GCLIENT_LOG_ERR__) == "function" then
                __GCLIENT_LOG_ERR__("[Lua226CompatShim] " .. tostring(runErr))
              end
            end
          end
        end
      end
    end
  end
  return false
end
)LUA";

bool tryLoadHostRuntimeShim(lua_State* L) {
    static constexpr const char* kHostPaths[] = {
        "compat_axmol_runtime.lua",
        "scripts/compat_axmol_runtime.lua",
        "bootstrap/compat_axmol_runtime.lua",
        "Resources/scripts/compat_axmol_runtime.lua",
        "lua_scripts/compat_axmol_runtime.lua",
    };
    for (const char* rel : kHostPaths) {
        std::ifstream ifs(rel, std::ios::binary);
        if (!ifs) continue;
        std::string src((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
        if (src.empty()) continue;
        const std::string chunkName = std::string("@") + rel;
        if (luaL_loadbuffer(L, src.data(), src.size(), chunkName.c_str()) == 0 &&
            lua_pcall(L, 0, 0, 0) == 0) {
            lua_getglobal(L, "package");
            if (lua_istable(L, -1)) {
                lua_getfield(L, -1, "loaded");
                if (lua_istable(L, -1)) {
                    lua_pushboolean(L, 1);
                    lua_setfield(L, -2, "compat_axmol_runtime");
                }
                lua_pop(L, 1);
            }
            lua_pop(L, 1);
            return true;
        }
        lua_pop(L, 1);
    }
    return false;
}

} // namespace

bool InstallLua226CompatShim(lua_State* L) {
    if (!L) return false;
    const int topBefore = lua_gettop(L);

    std::string fullSource;
    fullSource.reserve(20480);
    for (const char* chunk : kLua226CompatChunks) {
        if (chunk) fullSource.append(chunk);
    }
    if (luaL_loadbuffer(L, fullSource.data(), fullSource.size(), "@Lua226CompatShim.lua") != 0 ||
        lua_pcall(L, 0, 0, 0) != 0) {
        const char* err = lua_tostring(L, -1);
        gclient::diagnostics::CrashAndTelemetry::log(
            gclient::diagnostics::LogLevel::Error,
            "Lua226CompatShim",
            "Failed to install Lua 2.2.6 compat shim: %s",
            err ? err : "(null)");
        lua_settop(L, topBefore);
        return false;
    }

    // Prefer layering external compat_axmol_runtime.lua when present on disk (via ax.FileUtils or host FS).
    bool loadedViaFu = false;
    if (luaL_loadstring(L, kExternalShimLoaderChunk) == 0 && lua_pcall(L, 0, 1, 0) == 0) {
        loadedViaFu = lua_toboolean(L, -1) != 0;
    }
    lua_settop(L, topBefore);
    if (!loadedViaFu) {
        tryLoadHostRuntimeShim(L);
        lua_settop(L, topBefore);
    }
    return true;
}

} // namespace gclient::compat
