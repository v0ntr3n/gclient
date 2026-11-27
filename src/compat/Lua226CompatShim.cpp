#include "compat/Lua226CompatShim.h"
#include "diagnostics/CrashAndTelemetry.h"

extern "C" {
#include "lua.h"
#include "lauxlib.h"
}

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

  -- Lua 5.1 / LuaJIT helpers expected by legacy game scripts
  string.gfind = string.gfind or string.gmatch
  math.mod     = math.mod or math.fmod
  unpack       = unpack or table.unpack

  -- 0. Self-contained Axmol ScriptHandlerMgr::HandlerType constants (matches axmol/core/Constants.lua)
  ax.Handler = ax.Handler or {}
  local _H = ax.Handler
  _H.NODE                            = _H.NODE or 0
  _H.MENU_CLICKED                    = _H.MENU_CLICKED or 1
  _H.CALLFUNC                        = _H.CALLFUNC or 2
  _H.SCHEDULE                        = _H.SCHEDULE or 3
  _H.TOUCHES                         = _H.TOUCHES or 4
  _H.KEYPAD                          = _H.KEYPAD or 5
  _H.ACCELEROMETER                   = _H.ACCELEROMETER or 6
  _H.CONTROL_TOUCH_DOWN              = _H.CONTROL_TOUCH_DOWN or 7
  _H.CONTROL_TOUCH_DRAG_INSIDE       = _H.CONTROL_TOUCH_DRAG_INSIDE or 8
  _H.CONTROL_TOUCH_DRAG_OUTSIDE      = _H.CONTROL_TOUCH_DRAG_OUTSIDE or 9
  _H.CONTROL_TOUCH_DRAG_ENTER        = _H.CONTROL_TOUCH_DRAG_ENTER or 10
  _H.CONTROL_TOUCH_DRAG_EXIT         = _H.CONTROL_TOUCH_DRAG_EXIT or 11
  _H.CONTROL_TOUCH_UP_INSIDE         = _H.CONTROL_TOUCH_UP_INSIDE or 12
  _H.CONTROL_TOUCH_UP_OUTSIDE        = _H.CONTROL_TOUCH_UP_OUTSIDE or 13
  _H.CONTROL_TOUCH_UP_CANCEL         = _H.CONTROL_TOUCH_UP_CANCEL or 14
  _H.CONTROL_VALUE_CHANGED           = _H.CONTROL_VALUE_CHANGED or 15
  _H.WEBSOCKET_OPEN                  = _H.WEBSOCKET_OPEN or 16
  _H.WEBSOCKET_MESSAGE               = _H.WEBSOCKET_MESSAGE or 17
  _H.WEBSOCKET_CLOSE                 = _H.WEBSOCKET_CLOSE or 18
  _H.WEBSOCKET_ERROR                 = _H.WEBSOCKET_ERROR or 19
  _H.GL_NODE_DRAW                    = _H.GL_NODE_DRAW or 20
  _H.SCROLLVIEW_SCROLL               = _H.SCROLLVIEW_SCROLL or 21
  _H.SCROLLVIEW_ZOOM                 = _H.SCROLLVIEW_ZOOM or 22
  _H.TABLECELL_TOUCHED               = _H.TABLECELL_TOUCHED or 23
  _H.TABLECELL_HIGHLIGHT             = _H.TABLECELL_HIGHLIGHT or 24
  _H.TABLECELL_UNHIGHLIGHT           = _H.TABLECELL_UNHIGHLIGHT or 25
  _H.TABLECELL_WILL_RECYCLE          = _H.TABLECELL_WILL_RECYCLE or 26
  _H.TABLECELL_SIZE_FOR_INDEX        = _H.TABLECELL_SIZE_FOR_INDEX or 27
  _H.TABLECELL_AT_INDEX              = _H.TABLECELL_AT_INDEX or 28
  _H.TABLEVIEW_NUMS_OF_CELLS         = _H.TABLEVIEW_NUMS_OF_CELLS or 29
  _H.HTTPREQUEST_STATE_CHANGE        = _H.HTTPREQUEST_STATE_CHANGE or 30
  _H.ASSETSMANAGER_PROGRESS          = _H.ASSETSMANAGER_PROGRESS or 31
  _H.ASSETSMANAGER_SUCCESS           = _H.ASSETSMANAGER_SUCCESS or 32
  _H.ASSETSMANAGER_ERROR             = _H.ASSETSMANAGER_ERROR or 33
  _H.STUDIO_EVENT_LISTENER           = _H.STUDIO_EVENT_LISTENER or 34
  _H.ARMATURE_EVENT                  = _H.ARMATURE_EVENT or 35
  _H.EVENT_ACC                       = _H.EVENT_ACC or 36
  _H.EVENT_CUSTIOM                   = _H.EVENT_CUSTIOM or 37
  _H.EVENT_KEYBOARD_PRESSED          = _H.EVENT_KEYBOARD_PRESSED or 38
  _H.EVENT_KEYBOARD_RELEASED         = _H.EVENT_KEYBOARD_RELEASED or 39
  _H.EVENT_TOUCH_BEGAN               = _H.EVENT_TOUCH_BEGAN or 40
  _H.EVENT_TOUCH_MOVED               = _H.EVENT_TOUCH_MOVED or 41
  _H.EVENT_TOUCH_ENDED               = _H.EVENT_TOUCH_ENDED or 42
  _H.EVENT_TOUCH_CANCELLED           = _H.EVENT_TOUCH_CANCELLED or 43
  _H.EVENT_TOUCHES_BEGAN             = _H.EVENT_TOUCHES_BEGAN or 44
)LUA",
    R"LUA(  _H.EVENT_TOUCHES_MOVED             = _H.EVENT_TOUCHES_MOVED or 45
  _H.EVENT_TOUCHES_ENDED             = _H.EVENT_TOUCHES_ENDED or 46
  _H.EVENT_TOUCHES_CANCELLED         = _H.EVENT_TOUCHES_CANCELLED or 47
  _H.EVENT_MOUSE_DOWN                = _H.EVENT_MOUSE_DOWN or 48
  _H.EVENT_MOUSE_UP                  = _H.EVENT_MOUSE_UP or 49
  _H.EVENT_MOUSE_MOVE                = _H.EVENT_MOUSE_MOVE or 50
  _H.EVENT_MOUSE_SCROLL              = _H.EVENT_MOUSE_SCROLL or 51
  _H.EVENT_SPINE                     = _H.EVENT_SPINE or 52
  _H.EVENT_PHYSICS_CONTACT_BEGIN     = _H.EVENT_PHYSICS_CONTACT_BEGIN or 53
  _H.EVENT_PHYSICS_CONTACT_PRESOLVE  = _H.EVENT_PHYSICS_CONTACT_PRESOLVE or 54
  _H.EVENT_PHYSICS_CONTACT_POSTSOLVE = _H.EVENT_PHYSICS_CONTACT_POSTSOLVE or 55
  _H.EVENT_PHYSICS_CONTACT_SEPARATE  = _H.EVENT_PHYSICS_CONTACT_SEPARATE or 56
  _H.EVENT_FOCUS                     = _H.EVENT_FOCUS or 57
  _H.EVENT_SPINE_ANIMATION_START     = _H.EVENT_SPINE_ANIMATION_START or 64
  _H.EVENT_SPINE_ANIMATION_END       = _H.EVENT_SPINE_ANIMATION_END or 65
  _H.EVENT_SPINE_ANIMATION_COMPLETE  = _H.EVENT_SPINE_ANIMATION_COMPLETE or 66
  _H.EVENT_SPINE_ANIMATION_EVENT     = _H.EVENT_SPINE_ANIMATION_EVENT or 67

  -- 1. Geometry & Color Value Constructors (Axmol LuaBasicConversions reads {x=,y=}, {width=,height=}, {r=,g=,b=,a=})
  function CCPoint(x, y)
    if type(x) == "table" then return { x = x.x or x[1] or 0, y = x.y or x[2] or 0 } end
    return { x = tonumber(x) or 0, y = tonumber(y) or 0 }
  end
  ccp         = CCPoint
  CCPointMake = CCPoint

  function CCSize(w, h)
    if type(w) == "table" then
      local rw = w.width or w.x or w[1] or 0
      local rh = w.height or w.y or w[2] or 0
      return { width = rw, height = rh, x = rw, y = rh }
    end
    local rw = tonumber(w) or 0
    local rh = tonumber(h) or 0
    return { width = rw, height = rh, x = rw, y = rh }
  end
  CCSizeMake = CCSize

  function CCRect(x, y, w, h)
    if type(x) == "table" then
      return { x = x.x or 0, y = x.y or 0, width = x.width or 0, height = x.height or 0 }
    end
    return {
      x = tonumber(x) or 0,
      y = tonumber(y) or 0,
      width = tonumber(w) or 0,
      height = tonumber(h) or 0,
    }
  end
  CCRectMake = CCRect

  CCPointZero = { x = 0, y = 0 }
  CCSizeZero  = { width = 0, height = 0, x = 0, y = 0 }
  CCRectZero  = { x = 0, y = 0, width = 0, height = 0 }

  function ccc3(r, g, b)
    return { r = tonumber(r) or 0, g = tonumber(g) or 0, b = tonumber(b) or 0 }
  end
  function ccc4(r, g, b, a)
    return { r = tonumber(r) or 0, g = tonumber(g) or 0, b = tonumber(b) or 0, a = tonumber(a) or 255 }
  end
  function ccc4f(r, g, b, a)
    return { r = tonumber(r) or 0, g = tonumber(g) or 0, b = tonumber(b) or 0, a = tonumber(a) or 1 }
  end

  ccWHITE   = ccc3(255, 255, 255)
  ccYELLOW  = ccc3(255, 255, 0)
  ccBLUE    = ccc3(0, 0, 255)
  ccGREEN   = ccc3(0, 255, 0)
  ccRED     = ccc3(255, 0, 0)
  ccMAGENTA = ccc3(255, 0, 255)
  ccBLACK   = ccc3(0, 0, 0)
  ccORANGE  = ccc3(255, 127, 0)
  ccGRAY    = ccc3(166, 166, 166)

  function ccpAdd(v1, v2) return { x = v1.x + v2.x, y = v1.y + v2.y } end
  function ccpSub(v1, v2) return { x = v1.x - v2.x, y = v1.y - v2.y } end
  function ccpMult(v, s)  return { x = v.x * s, y = v.y * s } end
  function ccpMidpoint(v1, v2) return { x = (v1.x + v2.x) * 0.5, y = (v1.y + v2.y) * 0.5 } end
  function ccpDot(v1, v2) return v1.x * v2.x + v1.y * v2.y end
  function ccpLengthSQ(v) return v.x * v.x + v.y * v.y end
)LUA",
    R"LUA(  function ccpLength(v)   return math.sqrt(v.x * v.x + v.y * v.y) end
  function ccpDistanceSQ(v1, v2)
    local dx, dy = v1.x - v2.x, v1.y - v2.y
    return dx * dx + dy * dy
  end
  function ccpDistance(v1, v2) return math.sqrt(ccpDistanceSQ(v1, v2)) end
  function ccpNormalize(v)
    local l = ccpLength(v)
    if l <= 1e-7 then return { x = 0, y = 0 } end
    return { x = v.x / l, y = v.y / l }
  end
  function CCRectContainsPoint(rect, pt)
    if not rect or not pt then return false end
    return pt.x >= rect.x and pt.x <= (rect.x + rect.width) and
           pt.y >= rect.y and pt.y <= (rect.y + rect.height)
  end
  function CCRectIntersectsRect(a, b)
    if not a or not b then return false end
    return not (a.x > b.x + b.width or a.x + a.width < b.x or
                a.y > b.y + b.height or a.y + a.height < b.y)
  end

  -- 2. Legacy Cocos2d-x 2.2.6 Global Enums & Constants
  kResolutionExactFit    = 0
  kResolutionNoBorder    = 1
  kResolutionShowAll     = 2
  kResolutionFixedHeight = 3
  kResolutionFixedWidth  = 4
  kResolutionUnKnown     = 5

  kCCTextAlignmentLeft   = 0
  kCCTextAlignmentCenter = 1
  kCCTextAlignmentRight  = 2

  kCCVerticalTextAlignmentTop    = 0
  kCCVerticalTextAlignmentCenter = 1
  kCCVerticalTextAlignmentBottom = 2

  kCCTexture2DPixelFormat_RGBA8888 = 2
  kCCTexture2DPixelFormat_RGB888   = 3
  kCCTexture2DPixelFormat_RGB565   = 4
  kCCTexture2DPixelFormat_A8       = 5
  kCCTexture2DPixelFormat_RGBA4444 = 7
  kCCTexture2DPixelFormat_RGB5A1   = 8

  kCCMenuHandlerPriority = -128
  kCCNodeOnEnter = 0
  kCCNodeOnExit = 1
  kCCNodeOnEnterTransitionDidFinish = 2
  kCCNodeOnExitTransitionDidStart = 3
  kCCNodeOnCleanup = 4

  GL_ZERO                = 0
  GL_ONE                 = 1
  GL_SRC_COLOR           = 0x0300
  GL_ONE_MINUS_SRC_COLOR = 0x0301
  GL_SRC_ALPHA           = 0x0302
  GL_ONE_MINUS_SRC_ALPHA = 0x0303
  GL_DST_ALPHA           = 0x0304
  GL_ONE_MINUS_DST_ALPHA = 0x0305
  GL_DST_COLOR           = 0x0306
  GL_ONE_MINUS_DST_COLOR = 0x0307

  -- CocoStudio 1.x UI Enum Constants
  LAYOUT_COLOR_NONE          = 0
  LAYOUT_COLOR_SOLID         = 1
  LAYOUT_COLOR_GRADIENT      = 2

  LAYOUT_ABSOLUTE            = 0
  LAYOUT_LINEAR_VERTICAL     = 1
  LAYOUT_LINEAR_HORIZONTAL   = 2
  LAYOUT_RELATIVE            = 3

  BRIGHT_NONE                = -1
  BRIGHT_NORMAL              = 0
  BRIGHT_HIGHLIGHT           = 1

  UI_TEX_TYPE_LOCAL          = 0
  UI_TEX_TYPE_PLIST          = 1

  TOUCH_EVENT_BEGAN          = 0
  TOUCH_EVENT_MOVED          = 1
  TOUCH_EVENT_ENDED          = 2
  TOUCH_EVENT_CANCELED       = 3

  SIZE_ABSOLUTE              = 0
  SIZE_PERCENT               = 1
  POSITION_ABSOLUTE          = 0
  POSITION_PERCENT           = 1

  CHECKBOX_STATE_EVENT_SELECTED   = 0
  CHECKBOX_STATE_EVENT_UNSELECTED = 1

  LoadingBarTypeLeft         = 0
  LoadingBarTypeRight        = 1

  SCROLLVIEW_DIR_NONE        = 0
  SCROLLVIEW_DIR_VERTICAL    = 1
  SCROLLVIEW_DIR_HORIZONTAL  = 2
  SCROLLVIEW_DIR_BOTH        = 3

  LISTVIEW_GRAVITY_LEFT              = 0
  LISTVIEW_GRAVITY_RIGHT             = 1
  LISTVIEW_GRAVITY_CENTER_HORIZONTAL = 2
  LISTVIEW_GRAVITY_TOP               = 3
  LISTVIEW_GRAVITY_BOTTOM            = 4
  LISTVIEW_GRAVITY_CENTER_VERTICAL   = 5

  TEXTFIELD_EVENT_ATTACH_WITH_IME = 0
  TEXTFIELD_EVENT_DETACH_WITH_IME = 1
  TEXTFIELD_EVENT_INSERT_TEXT     = 2
  TEXTFIELD_EVENT_DELETE_BACKWARD = 3

  -- 3. tolua.cast / tolua.isnull / tolua.type Compatibility Map
  tolua = tolua or {}
)LUA",
    R"LUA(  local _orig_tolua_cast   = tolua.cast
  local _orig_tolua_isnull = tolua.isnull

  local _toluaTypeMap = {
    CCObject            = "ax.Object",
    CCNode              = "ax.Node",
    CCNodeRGBA          = "ax.Node",
    CCScene             = "ax.Scene",
    CCLayer             = "ax.Layer",
    CCLayerColor        = "ax.LayerColor",
    CCLayerGradient     = "ax.LayerGradient",
    CCMenu              = "ax.Menu",
    CCMenuItem          = "ax.MenuItem",
    CCMenuItemImage     = "ax.MenuItemImage",
    CCMenuItemSprite    = "ax.MenuItemSprite",
    CCMenuItemLabel     = "ax.MenuItemLabel",
    CCSprite            = "ax.Sprite",
    CCSpriteBatchNode   = "ax.SpriteBatchNode",
    CCSpriteFrame       = "ax.SpriteFrame",
    CCSpriteFrameCache  = "ax.SpriteFrameCache",
    CCTexture2D         = "ax.Texture2D",
    CCTextureCache      = "ax.TextureCache",
    CCDirector          = "ax.Director",
    CCScheduler         = "ax.Scheduler",
    CCFileUtils         = "ax.FileUtils",
    CCUserDefault       = "ax.UserDefault",
    CCApplication       = "ax.Application",
    CCRenderTexture     = "ax.RenderTexture",
    CCClippingNode      = "ax.ClippingNode",
    CCDrawNode          = "ax.DrawNode",
    CCProgressTimer     = "ax.ProgressTimer",
    CCParticleSystemQuad= "ax.ParticleSystemQuad",
    CCTMXTiledMap       = "ax.TMXTiledMap",
    CCLabelTTF          = "ax.Label",
    CCLabelBMFont       = "ax.Label",
    CCLabelAtlas        = "ax.LabelAtlas",
    CCScale9Sprite      = "axui.Scale9Sprite",
    CCEditBox           = "axui.EditBox",
    CCScrollView        = "ax.ScrollView",
    CCTableView         = "ax.TableView",
    CCTableViewCell     = "ax.TableViewCell",
    CCControlButton     = "ax.ControlButton",
    Widget              = "axui.Widget",
    UIWidget            = "axui.Widget",
    Layout              = "axui.Layout",
    UILayout            = "axui.Layout",
    Panel               = "axui.Layout",
    Button              = "axui.Button",
    UIButton            = "axui.Button",
    TextButton          = "axui.Button",
    CheckBox            = "axui.CheckBox",
    UICheckBox          = "axui.CheckBox",
    ImageView           = "axui.ImageView",
    UIImageView         = "axui.ImageView",
    Label               = "axui.Text",
    UILabel             = "axui.Text",
    Text                = "axui.Text",
    TextArea            = "axui.Text",
    LabelAtlas          = "axui.TextAtlas",
    UILabelAtlas        = "axui.TextAtlas",
    TextAtlas           = "axui.TextAtlas",
    LabelBMFont         = "axui.TextBMFont",
    UILabelBMFont       = "axui.TextBMFont",
    TextBMFont          = "axui.TextBMFont",
    LoadingBar          = "axui.LoadingBar",
    UILoadingBar        = "axui.LoadingBar",
    Slider              = "axui.Slider",
    UISlider            = "axui.Slider",
    TextField           = "axui.TextField",
    UITextField         = "axui.TextField",
    ScrollView          = "axui.ScrollView",
    UIScrollView        = "axui.ScrollView",
    DragPanel           = "axui.ScrollView",
    ListView            = "axui.ListView",
    UIListView          = "axui.ListView",
    PageView            = "axui.PageView",
    UIPageView          = "axui.PageView",
    RichText            = "axui.RichText",
    CCArmature          = "ccs.Armature",
    CCArmatureAnimation = "ccs.ArmatureAnimation",
    CCBone              = "ccs.Bone",
    CCSkin              = "ccs.Skin",
  }

  tolua.cast = function(obj, typeName)
)LUA",
    R"LUA(    if obj == nil then return nil end
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
    if _orig_tolua_isnull and type(obj) == "userdata" then
      return _orig_tolua_isnull(obj)
    end
    return false
  end

  if not tolua.getpeer then
    local _peers = setmetatable({}, { __mode = "k" })
    tolua.setpeer = function(u, t) _peers[u] = t end
    tolua.getpeer = function(u) return _peers[u] end
  end

  -- 4. Core Global Class Aliases
  CCObject             = ax.Object
  CCNode               = ax.Node
  CCNodeRGBA           = ax.Node
  CCScene              = ax.Scene
  CCLayer              = ax.Layer
  CCLayerRGBA          = ax.Layer
  CCLayerColor         = ax.LayerColor
  CCLayerGradient      = ax.LayerGradient
  CCMenu               = ax.Menu
  CCMenuItem           = ax.MenuItem
  CCMenuItemImage      = ax.MenuItemImage
  CCMenuItemSprite     = ax.MenuItemSprite
  CCMenuItemLabel      = ax.MenuItemLabel
  CCMenuItemFont       = ax.MenuItemFont
  CCMenuItemToggle     = ax.MenuItemToggle
  CCSprite             = ax.Sprite
  CCSpriteBatchNode    = ax.SpriteBatchNode
  CCSpriteFrame        = ax.SpriteFrame
  CCSpriteFrameCache   = ax.SpriteFrameCache
  CCTexture2D          = ax.Texture2D
  CCTextureCache       = ax.TextureCache
  CCDirector           = ax.Director
  CCScheduler          = ax.Scheduler
  CCFileUtils          = ax.FileUtils
  CCUserDefault        = ax.UserDefault
  CCApplication        = ax.Application
  CCRenderTexture      = ax.RenderTexture
  CCClippingNode       = ax.ClippingNode
  CCDrawNode           = ax.DrawNode
  CCProgressTimer      = ax.ProgressTimer
  CCMotionStreak       = ax.MotionStreak
  CCParticleSystemQuad = ax.ParticleSystemQuad
  CCTMXTiledMap        = ax.TMXTiledMap
  CCLabelTTF           = ax.Label
  if ax.Label then
    CCLabelBMFont = setmetatable({
      create = function(cls, str, fntFile, width, hAlign, imageOffset)
        if ax.Label.createWithBMFont then
          return ax.Label:createWithBMFont(
            tostring(fntFile or ""),
            tostring(str or ""),
            hAlign or 0,
            tonumber(width) or 0,
            imageOffset or CCPointZero)
        end
        return ax.Label:create()
      end,
    }, { __index = ax.Label })
  end
  CCLabelAtlas         = ax.LabelAtlas
  CCScale9Sprite       = axui.Scale9Sprite
  CCEditBox            = axui.EditBox
  CCScrollView         = ax.ScrollView
  CCTableView          = ax.TableView
  CCTableViewCell      = ax.TableViewCell
  CCControlButton      = ax.ControlButton
  CCAnimation          = ax.Animation
  CCAnimationCache     = ax.AnimationCache
  CCAnimate            = ax.Animate

  -- UI & CocoStudio Global Aliases
  Widget               = axui.Widget
  UIWidget             = axui.Widget
  Layout               = axui.Layout
  UILayout             = axui.Layout
  Panel                = axui.Layout
  Button               = axui.Button
  UIButton             = axui.Button
  TextButton           = axui.Button
  CheckBox             = axui.CheckBox
  UICheckBox           = axui.CheckBox
  ImageView            = axui.ImageView
)LUA",
    R"LUA(  UIImageView          = axui.ImageView
  Label                = axui.Text
  UILabel              = axui.Text
  LabelAtlas           = axui.TextAtlas
  UILabelAtlas         = axui.TextAtlas
  LabelBMFont          = axui.TextBMFont
  UILabelBMFont        = axui.TextBMFont
  LoadingBar           = axui.LoadingBar
  UILoadingBar         = axui.LoadingBar
  Slider               = axui.Slider
  UISlider             = axui.Slider
  TextField            = axui.TextField
  UITextField          = axui.TextField
  ScrollView           = axui.ScrollView
  UIScrollView         = axui.ScrollView
  ListView             = axui.ListView
  UIListView           = axui.ListView
  PageView             = axui.PageView
  UIPageView           = axui.PageView
  UIHelper             = axui.Helper
  LinearLayoutParameter   = axui.LinearLayoutParameter
  RelativeLayoutParameter = axui.RelativeLayoutParameter
  Margin               = function(l, t, r, b)
    return { left = l or 0, top = t or 0, right = r or 0, bottom = b or 0 }
  end

  GUIReader             = ccs.GUIReader
  SceneReader           = ccs.SceneReader
  ActionManager         = ccs.ActionManagerEx
  ActionManagerEx       = ccs.ActionManagerEx
  CCArmature            = ccs.Armature
  CCArmatureDataManager = ccs.ArmatureDataManager
  CCArmatureAnimation   = ccs.ArmatureAnimation
  CCBone                = ccs.Bone
  CCSkin                = ccs.Skin

  -- 5. Action Classes & CCArray Action Unpacking (CCSequence / CCSpawn)
  CCAction                 = ax.Action
  CCFiniteTimeAction       = ax.FiniteTimeAction
  CCActionInterval         = ax.ActionInterval
  CCSpeed                  = ax.Speed
  CCFollow                 = ax.Follow
  CCRepeat                 = ax.Repeat
  CCRepeatForever          = ax.RepeatForever
  CCDelayTime              = ax.DelayTime
  CCCallFunc               = ax.CallFunc
  CCCallFuncN              = ax.CallFunc
  CCMoveTo                 = ax.MoveTo
  CCMoveBy                 = ax.MoveBy
  CCScaleTo                = ax.ScaleTo
  CCScaleBy                = ax.ScaleBy
  CCRotateTo               = ax.RotateTo
  CCRotateBy               = ax.RotateBy
  CCSkewTo                 = ax.SkewTo
  CCSkewBy                 = ax.SkewBy
  CCJumpTo                 = ax.JumpTo
  CCJumpBy                 = ax.JumpBy
  CCBezierTo               = ax.BezierTo
  CCBezierBy               = ax.BezierBy
  CCBlink                  = ax.Blink
  CCFadeIn                 = ax.FadeIn
  CCFadeOut                = ax.FadeOut
  CCFadeTo                 = ax.FadeTo
  CCTintTo                 = ax.TintTo
  CCTintBy                 = ax.TintBy
  CCShow                   = ax.Show
  CCHide                   = ax.Hide
  CCPlace                  = ax.Place
  CCRemoveSelf             = ax.RemoveSelf
  CCToggleVisibility       = ax.ToggleVisibility
  CCOrbitCamera            = ax.OrbitCamera
  CCProgressTo             = ax.ProgressTo
  CCProgressFromTo         = ax.ProgressFromTo
  CCEaseIn                 = ax.EaseIn
  CCEaseOut                = ax.EaseOut
  CCEaseInOut              = ax.EaseInOut
  CCEaseSineIn             = ax.EaseSineIn
  CCEaseSineOut            = ax.EaseSineOut
  CCEaseSineInOut          = ax.EaseSineInOut
  CCEaseBackIn             = ax.EaseBackIn
  CCEaseBackOut            = ax.EaseBackOut
  CCEaseBackInOut          = ax.EaseBackInOut
  CCEaseBounceIn           = ax.EaseBounceIn
  CCEaseBounceOut          = ax.EaseBounceOut
  CCEaseBounceInOut        = ax.EaseBounceInOut
)LUA",
    R"LUA(  CCEaseElasticIn          = ax.EaseElasticIn
  CCEaseElasticOut         = ax.EaseElasticOut
  CCEaseElasticInOut       = ax.EaseElasticInOut
  CCEaseExponentialIn      = ax.EaseExponentialIn
  CCEaseExponentialOut     = ax.EaseExponentialOut
  CCEaseExponentialInOut   = ax.EaseExponentialInOut

  local function _unpackActionArgs(first, ...)
    if first ~= nil and select("#", ...) == 0 then
      if type(first) == "userdata" and type(first.count) == "function" and type(first.objectAtIndex) == "function" then
        local list = {}
        local n = first:count()
        for i = 0, n - 1 do
          list[#list + 1] = first:objectAtIndex(i)
        end
        return unpack(list)
      elseif type(first) == "table" and first[1] ~= nil then
        return unpack(first)
      end
    end
    return first, ...
  end

  if ax.Sequence then
    local _origSeqCreate = ax.Sequence.create
    CCSequence = setmetatable({
      create = function(cls, ...)
        return _origSeqCreate(ax.Sequence, _unpackActionArgs(...))
      end,
      createWithTwoActions = function(cls, a1, a2)
        return _origSeqCreate(ax.Sequence, a1, a2)
      end,
    }, { __index = ax.Sequence })
  end

  if ax.Spawn then
    local _origSpawnCreate = ax.Spawn.create
    CCSpawn = setmetatable({
      create = function(cls, ...)
        return _origSpawnCreate(ax.Spawn, _unpackActionArgs(...))
      end,
      createWithTwoActions = function(cls, a1, a2)
        return _origSpawnCreate(ax.Spawn, a1, a2)
      end,
    }, { __index = ax.Spawn })
  end

  if ax.CallFunc then
    CCCallFuncND = {
      create = function(cls, fn, data)
        return ax.CallFunc:create(function(sender)
          if fn then fn(sender, data) end
        end)
      end,
    }
  end

  -- 6. Singleton shared* Aliases & Legacy Methods
  if ax.Director then
    ax.Director.sharedDirector = ax.Director.sharedDirector or function(cls) return ax.Director:getInstance() end
    ax.Director.getOpenGLView  = ax.Director.getOpenGLView  or function(self) return self:getRenderView() end
    ax.Director.setDisplayStats= ax.Director.setDisplayStats or ax.Director.setStatsDisplay
  end

  CCEGLView = {
    sharedOpenGLView = function()
      return ax.Director:getInstance():getRenderView()
    end,
  }

  if ax.TextureCache then
    ax.TextureCache.sharedTextureCache = ax.TextureCache.sharedTextureCache or function(cls)
      return ax.Director:getInstance():getTextureCache()
    end
    ax.TextureCache.dumpCachedTextureInfo = ax.TextureCache.dumpCachedTextureInfo or function(self)
      if self.getCachedTextureInfo then print(self:getCachedTextureInfo()) end
    end
    ax.TextureCache.textureForKey = ax.TextureCache.textureForKey or ax.TextureCache.getTextureForKey
  end

  if ax.SpriteFrameCache then
    ax.SpriteFrameCache.sharedSpriteFrameCache = ax.SpriteFrameCache.sharedSpriteFrameCache or function(cls)
      return ax.SpriteFrameCache:getInstance()
    end
    ax.SpriteFrameCache.purgeSharedSpriteFrameCache = ax.SpriteFrameCache.purgeSharedSpriteFrameCache or function(cls)
      return ax.SpriteFrameCache:destroyInstance()
    end
    ax.SpriteFrameCache.spriteFrameByName = ax.SpriteFrameCache.spriteFrameByName or ax.SpriteFrameCache.getSpriteFrameByName
  end

  if ax.FileUtils then
    ax.FileUtils.sharedFileUtils = ax.FileUtils.sharedFileUtils or function(cls)
      return ax.FileUtils:getInstance()
    end
  end

  if ax.UserDefault then
)LUA",
    R"LUA(    ax.UserDefault.sharedUserDefault = ax.UserDefault.sharedUserDefault or function(cls)
      return ax.UserDefault:getInstance()
    end
  end

  if ax.Application then
    ax.Application.sharedApplication = ax.Application.sharedApplication or function(cls)
      return ax.Application:getInstance()
    end
  end

  if ax.AnimationCache then
    ax.AnimationCache.sharedAnimationCache = ax.AnimationCache.sharedAnimationCache or function(cls)
      return ax.AnimationCache:getInstance()
    end
    ax.AnimationCache.purgeSharedAnimationCache = ax.AnimationCache.purgeSharedAnimationCache or function(cls)
      return ax.AnimationCache:destroyInstance()
    end
    ax.AnimationCache.animationByName = ax.AnimationCache.animationByName or ax.AnimationCache.getAnimation
  end

  if ccs.GUIReader then
    ccs.GUIReader.shareReader = ccs.GUIReader.shareReader or function(cls) return ccs.GUIReader:getInstance() end
    ccs.GUIReader.purgeGUIReader = ccs.GUIReader.purgeGUIReader or function(cls) return ccs.GUIReader:destroyInstance() end
  end

  if ccs.SceneReader then
    ccs.SceneReader.sharedSceneReader = ccs.SceneReader.sharedSceneReader or function(cls) return ccs.SceneReader:getInstance() end
    ccs.SceneReader.purge               = ccs.SceneReader.purge or function(cls) return ccs.SceneReader:destroyInstance() end
  end

  if ccs.ActionManagerEx then
    ccs.ActionManagerEx.shareManager = ccs.ActionManagerEx.shareManager or function(cls) return ccs.ActionManagerEx:getInstance() end
    ccs.ActionManagerEx.purgeActionManager = ccs.ActionManagerEx.purgeActionManager or function(cls) return ccs.ActionManagerEx:destroyInstance() end
  end

  if ccs.ArmatureDataManager then
    ccs.ArmatureDataManager.sharedArmatureDataManager = ccs.ArmatureDataManager.sharedArmatureDataManager or function(cls)
      return ccs.ArmatureDataManager:getInstance()
    end
    ccs.ArmatureDataManager.purge = ccs.ArmatureDataManager.purge or function(cls)
      return ccs.ArmatureDataManager:destroyInstance()
    end
  end

  -- 7. CCNotificationCenter Compatibility Bus
  do
    local _observers = {}
    local _nc = {}
    function _nc:sharedNotificationCenter() return _nc end
    function _nc:purgeNotificationCenter() _observers = {} end
    function _nc:registerScriptObserver(target, handler, name)
      if not name or not handler then return end
      _observers[name] = _observers[name] or {}
      _observers[name][#_observers[name] + 1] = { target = target, handler = handler }
    end
    function _nc:unregisterScriptObserver(target, name)
      if not name or not _observers[name] then return end
      if target == nil then
        _observers[name] = nil
        return
      end
      local kept = {}
      for _, entry in ipairs(_observers[name]) do
        if entry.target ~= target then kept[#kept + 1] = entry end
      end
      _observers[name] = (#kept > 0) and kept or nil
    end
    function _nc:postNotification(name, obj)
      local list = name and _observers[name]
      if not list then return end
      local snapshot = {}
      for i = 1, #list do snapshot[i] = list[i] end
      for _, entry in ipairs(snapshot) do
        if type(entry.handler) == "function" then
          entry.handler(name, obj)
        end
      end
    end
    CCNotificationCenter = _nc
  end

  -- 8. Metatable Method Bridges (Node, Layer, ScrollView, Label, UI Widgets)
  if ax.Node then
    ax.Node.setZOrder            = ax.Node.setZOrder or ax.Node.setLocalZOrder
)LUA",
    R"LUA(    ax.Node.getZOrder            = ax.Node.getZOrder or ax.Node.getLocalZOrder
    ax.Node.setVertexZ           = ax.Node.setVertexZ or ax.Node.setPositionZ
    ax.Node.getVertexZ           = ax.Node.getVertexZ or ax.Node.getPositionZ
    ax.Node.boundingBox          = ax.Node.boundingBox or ax.Node.getBoundingBox
    ax.Node.numberOfRunningActions = ax.Node.numberOfRunningActions or ax.Node.getNumberOfRunningActions
    ax.Node.removeFromParentAndCleanup = ax.Node.removeFromParentAndCleanup or function(self, cleanup)
      return self:removeFromParent()
    end
    ax.Node.removeAllChildrenWithCleanup = ax.Node.removeAllChildrenWithCleanup or function(self, cleanup)
      return self:removeAllChildren()
    end
    ax.Node.pauseSchedulerAndActions = ax.Node.pauseSchedulerAndActions or ax.Node.pause
    ax.Node.resumeSchedulerAndActions = ax.Node.resumeSchedulerAndActions or ax.Node.resume
  end

  -- CCLayer 2.2.6 touch handler & priority bridge via ax.EventDispatcher
  if ax.Layer then
    local _layerTouchState = setmetatable({}, { __mode = "k" })
    local function _ensureState(self)
      local st = _layerTouchState[self]
      if not st then
        st = { enabled = false, priority = 0, swallows = false, isMulti = false, handler = nil, listener = nil }
        _layerTouchState[self] = st
      end
      return st
    end
    local function _rebuildLayerListener(self)
      local st = _ensureState(self)
      local disp = ax.Director:getInstance():getEventDispatcher()
      if st.listener then
        disp:removeEventListener(st.listener)
        st.listener = nil
      end
      if not st.enabled or type(st.handler) ~= "function" then return end

      if st.isMulti and ax.EventListenerTouchAllAtOnce then
        local l = ax.EventListenerTouchAllAtOnce:create()
        local function packTouches(touches)
          local tb = {}
          for _, t in ipairs(touches or {}) do
            local loc = t:getLocation()
            tb[#tb + 1] = loc.x
            tb[#tb + 1] = loc.y
            tb[#tb + 1] = t:getId()
          end
          return tb
        end
        l:registerScriptHandler(function(touches, event) st.handler("began", packTouches(touches)) end, ax.Handler.EVENT_TOUCHES_BEGAN)
        l:registerScriptHandler(function(touches, event) st.handler("moved", packTouches(touches)) end, ax.Handler.EVENT_TOUCHES_MOVED)
        l:registerScriptHandler(function(touches, event) st.handler("ended", packTouches(touches)) end, ax.Handler.EVENT_TOUCHES_ENDED)
        l:registerScriptHandler(function(touches, event) st.handler("cancelled", packTouches(touches)) end, ax.Handler.EVENT_TOUCHES_CANCELLED)
        disp:addEventListenerWithSceneGraphPriority(l, self)
        st.listener = l
      elseif ax.EventListenerTouchOneByOne then
        local l = ax.EventListenerTouchOneByOne:create()
        l:setSwallowTouches(st.swallows and true or false)
        l:registerScriptHandler(function(touch, event)
          local loc = touch:getLocation()
          local res = st.handler("began", loc.x, loc.y)
          return res ~= false
        end, ax.Handler.EVENT_TOUCH_BEGAN)
        l:registerScriptHandler(function(touch, event)
          local loc = touch:getLocation()
          st.handler("moved", loc.x, loc.y)
        end, ax.Handler.EVENT_TOUCH_MOVED)
        l:registerScriptHandler(function(touch, event)
          local loc = touch:getLocation()
          st.handler("ended", loc.x, loc.y)
        end, ax.Handler.EVENT_TOUCH_ENDED)
)LUA",
    R"LUA(        l:registerScriptHandler(function(touch, event)
          local loc = touch:getLocation()
          st.handler("cancelled", loc.x, loc.y)
        end, ax.Handler.EVENT_TOUCH_CANCELLED)
        disp:addEventListenerWithSceneGraphPriority(l, self)
        st.listener = l
      end
    end

    ax.Layer.setTouchEnabled = ax.Layer.setTouchEnabled or function(self, enabled)
      local st = _ensureState(self)
      st.enabled = enabled and true or false
      _rebuildLayerListener(self)
    end
    ax.Layer.isTouchEnabled = ax.Layer.isTouchEnabled or function(self)
      return _ensureState(self).enabled
    end
    ax.Layer.setTouchPriority = ax.Layer.setTouchPriority or function(self, p)
      _ensureState(self).priority = tonumber(p) or 0
    end
    ax.Layer.getTouchPriority = ax.Layer.getTouchPriority or function(self)
      return _ensureState(self).priority
    end
    ax.Layer.registerScriptTouchHandler = ax.Layer.registerScriptTouchHandler or function(self, fn, isMulti, priority, swallows)
      local st = _ensureState(self)
      st.handler  = fn
      st.isMulti  = isMulti and true or false
      st.priority = tonumber(priority) or st.priority
      st.swallows = swallows and true or false
      _rebuildLayerListener(self)
    end
    ax.Layer.unregisterScriptTouchHandler = ax.Layer.unregisterScriptTouchHandler or function(self)
      local st = _ensureState(self)
      st.handler = nil
      _rebuildLayerListener(self)
    end
  end

  if ax.ScrollView then
    ax.ScrollView.setMinAndMaxScale = ax.ScrollView.setMinAndMaxScale or function(self, minS, maxS)
      if minS and self.setMinScale then self:setMinScale(minS) end
      if maxS and self.setMaxScale then self:setMaxScale(maxS) end
    end
    ax.ScrollView.setTouchPriority = ax.ScrollView.setTouchPriority or function(self, p) end
  end

  if ax.Label then
    local _origLabelCreate = ax.Label.create
    ax.Label.create = function(cls, text, fontName, fontSize, dimensions, hAlign, vAlign)
      if text == nil then return _origLabelCreate(cls) end
      local fn = tostring(fontName or "Arial")
      if fn:sub(-4):lower() == ".fnt" and ax.Label.createWithBMFont then
        return ax.Label:createWithBMFont(fn, tostring(text), hAlign or 0, tonumber(fontSize) or 0, CCPointZero)
      end
      local fs = tonumber(fontSize) or 20
      if ax.FileUtils and ax.FileUtils:getInstance():isFileExist(fn) and ax.Label.createWithTTF then
        return ax.Label:createWithTTF(tostring(text), fn, fs, dimensions or CCSizeZero, hAlign or 0, vAlign or 0)
      end
      return ax.Label:createWithSystemFont(tostring(text), fn, fs, dimensions or CCSizeZero, hAlign or 0, vAlign or 0)
    end
  end

  -- UI Widget 2.2.6 Compatibility Methods
  if axui.Widget then
    axui.Widget.setSize = axui.Widget.setSize or axui.Widget.setContentSize
    axui.Widget.getSize = axui.Widget.getSize or axui.Widget.getContentSize
    axui.Widget.getWidgetByName = axui.Widget.getWidgetByName or function(self, name)
      return axui.Helper:seekWidgetByName(self, name)
    end
    axui.Widget.getWidgetByTag = axui.Widget.getWidgetByTag or function(self, tag)
      return axui.Helper:seekWidgetByTag(self, tag)
    end
    local _origAddTouchEventListener = axui.Widget.addTouchEventListener
    if _origAddTouchEventListener then
      axui.Widget.addTouchEventListener = function(self, arg1, arg2)
        if type(arg1) == "function" and arg2 == nil then
          return _origAddTouchEventListener(self, arg1)
)LUA",
    R"LUA(        elseif type(arg2) == "function" then
          local target = arg1
          return _origAddTouchEventListener(self, function(sender, eventType)
            arg2(target, sender, eventType)
          end)
        end
      end
    end
  end

  if axui.Text then
    axui.Text.setText        = axui.Text.setText or axui.Text.setString
    axui.Text.getStringValue = axui.Text.getStringValue or axui.Text.getString
  end
  if axui.TextBMFont then
    axui.TextBMFont.setText        = axui.TextBMFont.setText or axui.TextBMFont.setString
    axui.TextBMFont.getStringValue = axui.TextBMFont.setStringValue or axui.TextBMFont.getString
  end
  if axui.TextAtlas then
    axui.TextAtlas.setStringValue = axui.TextAtlas.setStringValue or axui.TextAtlas.setString
    axui.TextAtlas.getStringValue = axui.TextAtlas.getStringValue or axui.TextAtlas.getString
  end
  if axui.TextField then
    axui.TextField.setText        = axui.TextField.setText or axui.TextField.setString
    axui.TextField.getStringValue = axui.TextField.getStringValue or axui.TextField.getString
  end
  if axui.CheckBox then
    local _origCbAddEvent = axui.CheckBox.addEventListener or axui.CheckBox.addEventListenerCheckBox
    axui.CheckBox.addEventListenerCheckBox = function(self, arg1, arg2)
      if not _origCbAddEvent then return end
      if type(arg1) == "function" and arg2 == nil then
        return _origCbAddEvent(self, arg1)
      elseif type(arg2) == "function" then
        local target = arg1
        return _origCbAddEvent(self, function(sender, eventType)
          arg2(target, sender, eventType)
        end)
      end
    end
  end
end
)LUA",
};

} // namespace

bool InstallLua226CompatShim(lua_State* L) {
    if (!L) return false;
    std::string fullSource;
    fullSource.reserve(40960);
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
        lua_pop(L, 1);
        return false;
    }
    return true;
}

} // namespace gclient::compat
