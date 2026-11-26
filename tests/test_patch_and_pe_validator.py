#!/usr/bin/env python3
"""
tests/test_patch_and_pe_validator.py — Automated Unit & Integration Tests for:
  1. tools/patch_cocos2dx.py (0x00020206 version gate, exact CCLabelAtlas::updateAtlasValues
     guard, deferred atlas recovery, 32-byte-stride __iob_func + _M_IX86 __imp____iob_func,
     VS2022 v143 /MD vcxproj migration, idempotency, and fail-closed drift detection).
  2. tools/audit_pe_dependencies.py (synthetic PE32 0x014C & PE32+ 0x8664 binary generator,
     Import/Delay-Import/Export/RSDS CodeView parser, x64 rejection, MSVCR100 rejection,
     Debug/ASan CRT rejection, missing DLL detection, LuaJIT export & SHA-256 provenance gate,
     and BFS transitive staging).
  3. tools/validate_resources.py (Unicode/space/#/? SQLite RFC 8089 read-only URI validation
     and raw 0xFEFEFEFE undecrypted DB detection).
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import struct
import sys
import tempfile
import unittest
from typing import Dict, List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_module(name: str, rel_path: str):
    mod_path = REPO_ROOT / rel_path
    spec = importlib.util.spec_from_file_location(name, mod_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


patch_cocos2dx = _load_module("patch_cocos2dx", "tools/patch_cocos2dx.py")
audit_pe = _load_module("audit_pe_dependencies", "tools/audit_pe_dependencies.py")
validate_resources = _load_module("validate_resources", "tools/validate_resources.py")


# ==============================================================================
# Minimal Deterministic PE32 (0x014C) / PE32+ (0x8664) Binary Synthesizer
# ==============================================================================

def build_synthetic_pe(
    *,
    is_dll: bool = True,
    is_64bit: bool = False,
    imports: Optional[Dict[str, Sequence[str]]] = None,
    delay_imports: Optional[Dict[str, Sequence[str]]] = None,
    exports: Optional[Sequence[str]] = None,
    pdb_path: Optional[str] = None,
    dll_name_for_export: str = "synthetic.dll",
) -> bytes:
    """Builds a standards-compliant PE32 or PE32+ image with .rdata containing
    Import, Delay-Import, Export, and RSDS Debug directories."""
    imports = imports or {}
    delay_imports = delay_imports or {}
    exports = list(exports or [])

    sec_rva = 0x1000
    sec_raw_ptr = 0x400
    buf = bytearray()

    def cur_rva() -> int:
        return sec_rva + len(buf)

    def align4() -> None:
        while len(buf) % 4 != 0:
            buf.append(0)

    def align8() -> None:
        while len(buf) % 8 != 0:
            buf.append(0)

    def emit_cstr(s: str) -> int:
        rva = cur_rva()
        buf.extend(s.encode("ascii") + b"\x00")
        return rva

    ptr_size = 8 if is_64bit else 4
    ptr_fmt = "<Q" if is_64bit else "<I"

    # 1. Export Directory
    export_dir_rva = 0
    export_dir_size = 0
    if exports:
        sorted_exps = sorted(exports)
        name_rvas: List[int] = [emit_cstr(sym) for sym in sorted_exps]
        dll_name_rva = emit_cstr(dll_name_for_export)
        align4()
        funcs_rva = cur_rva()
        for i in range(len(sorted_exps)):
            buf.extend(struct.pack("<I", 0x2000 + i * 16))
        names_table_rva = cur_rva()
        for r in name_rvas:
            buf.extend(struct.pack("<I", r))
        ords_table_rva = cur_rva()
        for i in range(len(sorted_exps)):
            buf.extend(struct.pack("<H", i))
        align4()
        export_dir_rva = cur_rva()
        buf.extend(
            struct.pack(
                "<IIHHIIIIIII",
                0,
                0x65000000,
                0,
                0,
                dll_name_rva,
                1,
                len(sorted_exps),
                len(sorted_exps),
                funcs_rva,
                names_table_rva,
                ords_table_rva,
            )
        )
        export_dir_size = 40

    # 2. Standard Import Directory
    import_dir_rva = 0
    import_dir_size = 0
    if imports:
        imp_entries: List[Tuple[int, int, int]] = []
        for dll, syms in imports.items():
            dll_rva = emit_cstr(dll)
            ibn_rvas: List[int] = []
            for sym in syms:
                align4()
                ibn_rva = cur_rva()
                buf.extend(struct.pack("<H", 0) + sym.encode("ascii") + b"\x00")
                ibn_rvas.append(ibn_rva)
            align8()
            ilt_rva = cur_rva()
            for r in ibn_rvas:
                buf.extend(struct.pack(ptr_fmt, r))
            buf.extend(struct.pack(ptr_fmt, 0))
            iat_rva = cur_rva()
            for r in ibn_rvas:
                buf.extend(struct.pack(ptr_fmt, r))
            buf.extend(struct.pack(ptr_fmt, 0))
            imp_entries.append((ilt_rva, dll_rva, iat_rva))

        align4()
        import_dir_rva = cur_rva()
        for ilt_rva, dll_rva, iat_rva in imp_entries:
            buf.extend(struct.pack("<IIIII", ilt_rva, 0, 0, dll_rva, iat_rva))
        buf.extend(b"\x00" * 20)
        import_dir_size = (len(imp_entries) + 1) * 20

    # 3. Delay-Load Import Directory
    delay_dir_rva = 0
    delay_dir_size = 0
    if delay_imports:
        d_entries: List[Tuple[int, int, int]] = []
        for dll, syms in delay_imports.items():
            dll_rva = emit_cstr(dll)
            ibn_rvas = []
            for sym in syms:
                align4()
                ibn_rva = cur_rva()
                buf.extend(struct.pack("<H", 0) + sym.encode("ascii") + b"\x00")
                ibn_rvas.append(ibn_rva)
            align8()
            int_rva = cur_rva()
            for r in ibn_rvas:
                buf.extend(struct.pack(ptr_fmt, r))
            buf.extend(struct.pack(ptr_fmt, 0))
            iat_rva = cur_rva()
            for r in ibn_rvas:
                buf.extend(struct.pack(ptr_fmt, r))
            buf.extend(struct.pack(ptr_fmt, 0))
            d_entries.append((dll_rva, iat_rva, int_rva))

        align4()
        delay_dir_rva = cur_rva()
        for dll_rva, iat_rva, int_rva in d_entries:
            # grAttrs=1 (RVA-based), szName, phmod, pIAT, pINT, pBoundIAT, pUnloadIAT, dwTimeStamp
            buf.extend(struct.pack("<IIIIIIII", 1, dll_rva, 0, iat_rva, int_rva, 0, 0, 0))
        buf.extend(b"\x00" * 32)
        delay_dir_size = (len(d_entries) + 1) * 32

    # 4. RSDS CodeView Debug Directory
    debug_dir_rva = 0
    debug_dir_size = 0
    if pdb_path:
        align4()
        cv_rva = cur_rva()
        cv_raw_off = sec_raw_ptr + len(buf)
        cv_blob = b"RSDS" + (b"\x11" * 16) + struct.pack("<I", 1) + pdb_path.encode("utf-8") + b"\x00"
        buf.extend(cv_blob)
        align4()
        debug_dir_rva = cur_rva()
        buf.extend(
            struct.pack(
                "<IIHHIIII",
                0,
                0x65000000,
                0,
                0,
                2,  # IMAGE_DEBUG_TYPE_CODEVIEW
                len(cv_blob),
                cv_rva,
                cv_raw_off,
            )
        )
        debug_dir_size = 28

    if not buf:
        buf.extend(b"\x00" * 16)

    virtual_size = len(buf)
    raw_size = ((virtual_size + 0x1FF) // 0x200) * 0x200
    sec_padded = bytes(buf) + b"\x00" * (raw_size - virtual_size)

    # Assemble DOS + PE + COFF + Optional Header + 1 Section Header (.rdata)
    dos_hdr = bytearray(0x80)
    dos_hdr[0:2] = b"MZ"
    struct.pack_into("<I", dos_hdr, 0x3C, 0x80)

    machine = audit_pe.IMAGE_FILE_MACHINE_AMD64 if is_64bit else audit_pe.IMAGE_FILE_MACHINE_I386
    characteristics = 0x0102 | audit_pe.IMAGE_FILE_LARGE_ADDRESS_AWARE
    if is_dll:
        characteristics |= audit_pe.IMAGE_FILE_DLL

    data_dirs = [(0, 0)] * 16
    data_dirs[audit_pe.IMAGE_DIRECTORY_ENTRY_EXPORT] = (export_dir_rva, export_dir_size)
    data_dirs[audit_pe.IMAGE_DIRECTORY_ENTRY_IMPORT] = (import_dir_rva, import_dir_size)
    data_dirs[audit_pe.IMAGE_DIRECTORY_ENTRY_DEBUG] = (debug_dir_rva, debug_dir_size)
    data_dirs[audit_pe.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT] = (delay_dir_rva, delay_dir_size)

    dd_bytes = b"".join(struct.pack("<II", rva, sz) for rva, sz in data_dirs)
    size_of_image = 0x1000 + ((virtual_size + 0xFFF) // 0x1000) * 0x1000

    if not is_64bit:
        opt_fixed = struct.pack(
            "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
            audit_pe.PE_OPTIONAL_HDR32_MAGIC,
            14,
            38,  # MSVC v143 linker 14.38
            0,
            raw_size,
            0,
            0x1000,
            0x1000,
            0x1000,
            0x10000000 if is_dll else 0x00400000,
            0x1000,
            0x200,
            6,
            0,
            0,
            0,
            6,
            0,
            0,
            size_of_image,
            sec_raw_ptr,
            0,
            2,  # WINDOWS_GUI
            0x8140,
            0x100000,
            0x1000,
            0x100000,
            0x1000,
            0,
            16,
        )
    else:
        opt_fixed = struct.pack(
            "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
            audit_pe.PE_OPTIONAL_HDR64_MAGIC,
            14,
            38,
            0,
            raw_size,
            0,
            0x1000,
            0x1000,
            0x180000000 if is_dll else 0x140000000,
            0x1000,
            0x200,
            6,
            0,
            0,
            0,
            6,
            0,
            0,
            size_of_image,
            sec_raw_ptr,
            0,
            2,
            0x8160,
            0x100000,
            0x1000,
            0x100000,
            0x1000,
            0,
            16,
        )

    opt_hdr = opt_fixed + dd_bytes
    coff_hdr = struct.pack("<HHIIIHH", machine, 1, 0x65000000, 0, 0, len(opt_hdr), characteristics)
    sec_hdr = struct.pack(
        "<8sIIIIIIHHI",
        b".rdata\x00\x00",
        virtual_size,
        sec_rva,
        raw_size,
        sec_raw_ptr,
        0,
        0,
        0,
        0,
        0x40000040,
    )

    headers = bytes(dos_hdr) + b"PE\x00\x00" + coff_hdr + opt_hdr + sec_hdr
    assert len(headers) <= sec_raw_ptr
    headers_padded = headers + b"\x00" * (sec_raw_ptr - len(headers))
    return headers_padded + sec_padded


# ==============================================================================
# Mock Cocos2d-x 2.2.6 Source Tree Builder for Patcher Tests
# ==============================================================================

def create_mock_cocos2dx_226_tree(root: Path, version_hex: str = "0x00020206") -> None:
    def w(rel: str, content: str, crlf: bool = False) -> None:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if crlf:
            content = content.replace("\n", "\r\n")
        p.write_bytes(content.encode("utf-8"))

    w(
        "cocos2dx/include/cocos2d.h",
        f"#ifndef __COCOS2D_H__\n#define __COCOS2D_H__\n#define COCOS2D_VERSION {version_hex}\n#endif\n",
    )
    w("cocos2dx/platform/win32/CCStdC.cpp", "#include \"CCStdC.h\"\n")
    w(
        "cocos2dx/platform/win32/CCStdC.h",
        "#if _MSC_VER < 1800\n#define snprintf _snprintf\n#endif\n",
        crlf=True,
    )
    w(
        "cocos2dx/platform/CCFileUtils.h",
        """namespace cocos2d {
class CC_DLL CCFileUtils {
public:
    virtual unsigned char* getFileData(const char* pszFileName, const char* pszMode, unsigned long * pSize);
protected:
    CCFileUtils();
};
}
""",
    )
    w(
        "cocos2dx/platform/CCFileUtils.cpp",
        """#include "CCFileUtils.h"
namespace cocos2d {
unsigned char* CCFileUtils::getFileData(const char* pszFileName, const char* pszMode, unsigned long * pSize)
{
    unsigned char * pBuffer = NULL;
    *pSize = 0;
    do
    {
        std::string fullPath = fullPathForFilename(pszFileName);
        FILE *fp = fopen(fullPath.c_str(), pszMode);
        CC_BREAK_IF(!fp);
        fseek(fp,0,SEEK_END);
        *pSize = ftell(fp);
        fseek(fp,0,SEEK_SET);
        pBuffer = new unsigned char[*pSize];
        *pSize = fread(pBuffer,sizeof(unsigned char), *pSize,fp);
        fclose(fp);
    } while (0);
    return pBuffer;
}
}
""",
    )
    w(
        "cocos2dx/platform/win32/CCFileUtilsWin32.cpp",
        """#include "CCFileUtilsWin32.h"
bool CCFileUtilsWin32::isFileExist(const std::string& strFilePath)
{
    if (0 == strFilePath.length())
    {
        return false;
    }
    std::string strPath = strFilePath;
    if (!isAbsolutePath(strPath))
    { // Not absolute path, add the default root path at the beginning.
        strPath.insert(0, m_strDefaultResRootPath);
    }
    return GetFileAttributesA(strPath.c_str()) != -1 ? true : false;
}
""",
    )
    w(
        "cocos2dx/label_nodes/CCLabelAtlas.cpp",
        """#include "CCLabelAtlas.h"
namespace cocos2d {
void CCLabelAtlas::updateAtlasValues()
{
    unsigned int n = m_sString.length();
    ccV3F_C4B_T2F_Quad quad;
    const unsigned char *s = (unsigned char*)m_sString.c_str();
    CCTexture2D *texture = m_pTextureAtlas->getTexture();
    float textureWide = (float) texture->getPixelsWide();
    float textureHigh = (float) texture->getPixelsHigh();
    float itemWidthInPixels = m_uItemWidth * CC_CONTENT_SCALE_FACTOR();
    float itemHeightInPixels = m_uItemHeight * CC_CONTENT_SCALE_FACTOR();
    if (m_bIgnoreContentScaleFactor)
    {
        itemWidthInPixels = m_uItemWidth;
        itemHeightInPixels = m_uItemHeight;
    }
    for(unsigned int i = 0; i < n; i++) {
        unsigned char a = s[i] - m_uMapStartChar;
        float row = (float) (a % m_uItemsPerRow);
        float col = (float) (a / m_uItemsPerRow);
        float left = row * itemWidthInPixels / textureWide;
        float right = left + itemWidthInPixels / textureWide;
        float top = col * itemHeightInPixels / textureHigh;
        float bottom = top + itemHeightInPixels / textureHigh;
        quad.tl.texCoords.u = left;
        m_pTextureAtlas->updateQuad(&quad, i);
    }
}
}
""",
    )
    w(
        "cocos2dx/base_nodes/CCAtlasNode.cpp",
        """#include "CCAtlasNode.h"
namespace cocos2d {
void CCAtlasNode::calculateMaxItems()
{
    CCSize s = m_pTextureAtlas->getTexture()->getContentSize();
    if (m_bIgnoreContentScaleFactor)
    {
        s = m_pTextureAtlas->getTexture()->getContentSizeInPixels();
    }
    m_uItemsPerColumn = (int)(s.height / m_uItemHeight);
    m_uItemsPerRow = (int)(s.width / m_uItemWidth);
}
void CCAtlasNode::draw(void)
{
    CC_NODE_DRAW_SETUP();
    ccGLBlendFunc( m_tBlendFunc.src, m_tBlendFunc.dst );
    m_pTextureAtlas->drawQuads();
}
void CCAtlasNode::setTexture(CCTexture2D *texture)
{
    m_pTextureAtlas->setTexture(texture);
    this->updateBlendFunc();
    this->updateOpacityModifyRGB();
}
}
""",
    )
    w(
        "cocos2dx/CCDirector.cpp",
        """#include "CCDirector.h"
namespace cocos2d {
void CCDirector::createStatsLabel()
{
    CCTexture2D *texture = NULL;
    CCTextureCache *textureCache = CCTextureCache::sharedTextureCache();
    if( m_pFPSLabel && m_pSPFLabel )
    {
        CC_SAFE_RELEASE_NULL(m_pFPSLabel);
        CC_SAFE_RELEASE_NULL(m_pSPFLabel);
        CC_SAFE_RELEASE_NULL(m_pDrawsLabel);
        textureCache->removeTextureForKey("cc_fps_images");
        CCFileUtils::sharedFileUtils()->purgeCachedEntries();
    }
    CCTexture2DPixelFormat currentFormat = CCTexture2D::defaultAlphaPixelFormat();
    CCTexture2D::setDefaultAlphaPixelFormat(kCCTexture2DPixelFormat_RGBA4444);
    unsigned char *data = NULL;
    unsigned int data_len = 0;
    getFPSImageData(&data, &data_len);
    CCImage* image = new CCImage();
    bool isOK = image->initWithImageData(data, data_len);
    CCAssert(isOK, "The resource cc_fps_images is invalid!");
    texture = textureCache->addUIImage(image, "cc_fps_images");
    CC_SAFE_RELEASE(image);
}
}
""",
    )
    w(
        "cocos2dx/platform/CCEGLViewProtocol.cpp",
        """#include "CCEGLViewProtocol.h"
namespace cocos2d {
void CCEGLViewProtocol::setDesignResolutionSize(float width, float height, ResolutionPolicy resolutionPolicy)
{
    CCAssert(m_fScreenWidth > 0.0f && m_fScreenHeight > 0.0f, "screen size error");
    if (width == 0.0f || height == 0.0f)
    {
        return;
    }
    m_obDesignResolutionSize.setSize(width, height);
}
}
""",
    )
    w(
        "cocos2dx/platform/win32/CCEGLView.cpp",
        """#include "CCEGLView.h"
namespace cocos2d {
LRESULT CCEGLView::WindowProc(UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_SIZE:
        if (wParam == SIZE_RESTORED)
        {
            CCApplication::sharedApplication()->applicationWillEnterForeground();
        }
        else if (wParam == SIZE_MINIMIZED)
        {
            CCApplication::sharedApplication()->applicationDidEnterBackground();
        }
        break;
    }
    return 0;
}
}
""",
    )
    w(
        "cocos2dx/platform/CCImageCommon_cpp.h",
        """static void pngReadCallback(png_structp png_ptr, png_bytep data, png_size_t length) {}
bool CCImage::_initWithPngData(void * pData, int nDatalen)
{
    png_structp png_ptr = 0;
    png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, 0, 0, 0);
    return true;
}
bool CCImage::_initWithJpgData(void * data, int nSize)
{
    struct jpeg_decompress_struct cinfo;
    struct MyErrorMgr jerr;
    cinfo.err = jpeg_std_error(&jerr.pub);
    return true;
}
""",
    )
    w(
        "extensions/spine/Animation.c",
        """void _FFDTimeline_apply (const Timeline* timeline, Skeleton* skeleton, float lastTime, float time, Event** firedEvents, int* eventsCount, float alpha) {
    float frameTime = self->frames[frameIndex];
    float percent = 1 - (time - frameTime) / (self->frames[frameIndex + -1] - frameTime);
}
""",
    )

    # Mock legacy vcxproj files + stale MSVCR100 DLLs
    vcxproj_tpl = """<?xml version="1.0" encoding="utf-8"?>
<Project DefaultTargets="Build" ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <PropertyGroup Label="Configuration">
    <PlatformToolset>v110</PlatformToolset>
  </PropertyGroup>
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|Win32'">
    <ClCompile>
      <RuntimeLibrary>MultiThreadedDLL</RuntimeLibrary>
      <TreatWarningAsError>true</TreatWarningAsError>
    </ClCompile>
    <Link>
      <AdditionalDependencies>glew32.lib;pthreadVCE2.lib;libzlib.lib;lua51.lib;%(AdditionalDependencies)</AdditionalDependencies>
    </Link>
    <PreLinkEvent>
      <Command>if not exist "$(OutDir)" mkdir "$(OutDir)"
xcopy /Y /Q "$(ProjectDir)..\\..\\cocos2dx\\platform\\third_party\\win32\\libraries\\*.*" "$(OutDir)"</Command>
    </PreLinkEvent>
  </ItemDefinitionGroup>
</Project>
"""
    w("cocos2dx/proj.win32/cocos2d.vcxproj", vcxproj_tpl)
    w(
        "extensions/proj.win32/libExtensions.vcxproj",
        vcxproj_tpl.replace(
            "</Project>",
            '  <ItemGroup>\n    <ClCompile Include="..\\network\\HttpClient.cpp" />\n    <ClCompile Include="..\\AssetsManager\\AssetsManager.cpp" />\n  </ItemGroup>\n</Project>',
        ),
    )
    w("scripting/lua/proj.win32/liblua.vcxproj", vcxproj_tpl)

    for stale in (
        "scripting/lua/luajit/win32/lua51.dll",
        "cocos2dx/platform/third_party/win32/libraries/pthreadVCE2.dll",
        "cocos2dx/platform/third_party/win32/libraries/libcurl.dll",
    ):
        w(stale, "MZ_STALE_MSVCR100_BINARY")


# ==============================================================================
# Test Cases
# ==============================================================================

class TestCocos2dxPatcher(unittest.TestCase):
    def test_patch_226_exact_guards_vcxproj_and_idempotency(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cocos_root = Path(tmp) / "cocos2d-x-2.2.6"
            vcpkg_dir = Path(tmp) / "vcpkg_x86"
            (vcpkg_dir / "include").mkdir(parents=True)
            (vcpkg_dir / "lib").mkdir(parents=True)
            (vcpkg_dir / "bin").mkdir(parents=True)
            (vcpkg_dir / "lib" / "pthreadVC3.lib").write_bytes(b"LIB")
            (vcpkg_dir / "lib" / "zlib.lib").write_bytes(b"LIB")
            (vcpkg_dir / "lib" / "glew32.lib").write_bytes(b"LIB")

            create_mock_cocos2dx_226_tree(cocos_root)

            rc1 = patch_cocos2dx.main([str(cocos_root), "--vcpkg-installed", str(vcpkg_dir)])
            self.assertEqual(rc1, 0)

            label_cpp = (cocos_root / "cocos2dx/label_nodes/CCLabelAtlas.cpp").read_text(encoding="utf-8")
            self.assertIn("if (!m_pTextureAtlas ||", label_cpp)
            self.assertIn("!m_pTextureAtlas->getTexture() ||", label_cpp)
            self.assertIn("m_uItemsPerRow == 0)", label_cpp)

            atlas_cpp = (cocos_root / "cocos2dx/base_nodes/CCAtlasNode.cpp").read_text(encoding="utf-8")
            self.assertIn("GCLIENT_ATLAS_LIFECYCLE_GUARD", atlas_cpp)
            self.assertIn("updateAtlasValues()", atlas_cpp)

            iob_shim = (cocos_root / "cocos2dx/platform/win32/CCStdC.cpp").read_text(encoding="utf-8")
            self.assertIn("__imp____iob_func", iob_shim)
            self.assertIn("unsigned char raw[32]", iob_shim)

            cocos_vcxproj = (cocos_root / "cocos2dx/proj.win32/cocos2d.vcxproj").read_text(encoding="utf-8")
            self.assertIn("<PlatformToolset>v143</PlatformToolset>", cocos_vcxproj)
            self.assertIn("pthreadVC3.lib", cocos_vcxproj)
            self.assertNotIn("pthreadVCE2.lib", cocos_vcxproj)
            self.assertFalse((cocos_root / "scripting/lua/luajit/win32/lua51.dll").exists())

            # Second run must be 100% idempotent (exit 0, no duplicate guard blocks)
            rc2 = patch_cocos2dx.main([str(cocos_root), "--vcpkg-installed", str(vcpkg_dir)])
            self.assertEqual(rc2, 0)
            label_cpp_after = (cocos_root / "cocos2dx/label_nodes/CCLabelAtlas.cpp").read_text(encoding="utf-8")
            self.assertEqual(label_cpp, label_cpp_after)

    def test_patch_fails_closed_on_wrong_cocos_version_or_drifted_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            wrong_ver_root = Path(tmp) / "cocos_wrong_ver"
            create_mock_cocos2dx_226_tree(wrong_ver_root, version_hex="0x00020205")
            rc_ver = patch_cocos2dx.main([str(wrong_ver_root)])
            self.assertNotEqual(rc_ver, 0)

            drifted_root = Path(tmp) / "cocos_drifted"
            create_mock_cocos2dx_226_tree(drifted_root)
            (drifted_root / "cocos2dx/label_nodes/CCLabelAtlas.cpp").write_text(
                "// unexpected upstream rewrite without updateAtlasValues signature\n",
                encoding="utf-8",
            )
            rc_drift = patch_cocos2dx.main([str(drifted_root)])
            self.assertNotEqual(rc_drift, 0)


    def test_patch_pvr_rgba8_premul_and_armature_seam_fixes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cocos_root = Path(tmp) / "cocos2d-x-2.2.6"
            create_mock_cocos2dx_226_tree(cocos_root)

            def w_extra(rel: str, content: str) -> None:
                p = cocos_root / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(content, encoding="utf-8")

            w_extra(
                "cocos2dx/textures/CCTexture2D.cpp",
                """#include "CCTexture2D.h"
NS_CC_BEGIN
static bool PVRHaveAlphaPremultiplied_ = false;
bool CCTexture2D::initWithPVRFile(const char* file)
{
    CCTexturePVR *pvr = new CCTexturePVR;
    bool bRet = pvr->initWithContentsOfFile(file);
    if (bRet)
    {
        m_bHasPremultipliedAlpha = PVRHaveAlphaPremultiplied_;
        pvr->release();
    }
    return bRet;
}
NS_CC_END
""",
            )
            w_extra(
                "cocos2dx/textures/CCTexturePVR.cpp",
                """#include "CCTexturePVR.h"
NS_CC_BEGIN
#define kPVR3TexturePixelFormat_LA_88      0x000008080000616cULL
struct _pixel_formathash v3_pixel_formathash[] = {
\t{kPVR3TexturePixelFormat_LA_88,\t\t&PVRTableFormats[8] },
};
bool CCTexturePVR::unpackPVRv3Data(unsigned char* dataPointer, unsigned int dataLength)
{
    unsigned int pvr3TableElements = PVR3_MAX_TABLE_ELEMENTS;
    if (! CCConfiguration::sharedConfiguration()->supportsPVRTC())
    {
        pvr3TableElements = 9;
    }
    for(unsigned int i = 0; i < pvr3TableElements; i++)
    {
\t\tif( v3_pixel_formathash[i].pixelFormat == pixelFormat )
        {
            return true;
        }
    }
    return false;
}
bool CCTexturePVR::createGLTexture()
{
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, m_uWidth, m_uHeight, 0, GL_RGBA, GL_UNSIGNED_BYTE, 0);
    return true;
}
NS_CC_END
""",
            )
            w_extra(
                "extensions/CocoStudio/Armature/CCBone.cpp",
                """#include "CCBone.h"
NS_CC_EXT_BEGIN
void CCBone::updateColor()
{
    CCNode *display = m_pDisplayManager->getDisplayRenderNode();
    CCRGBAProtocol *protocol = dynamic_cast<CCRGBAProtocol *>(display);
    if(protocol != NULL)
    {
        protocol->setColor(ccc3(_displayedColor.r * m_pTweenData->r / 255, _displayedColor.g * m_pTweenData->g / 255, _displayedColor.b * m_pTweenData->b / 255));
        protocol->setOpacity(_displayedOpacity * m_pTweenData->a / 255);
    }
}
NS_CC_EXT_END
""",
            )
            w_extra(
                "extensions/CocoStudio/Armature/display/CCSkin.h",
                """#ifndef __CCSKIN_H__
#define __CCSKIN_H__
NS_CC_EXT_BEGIN
class CC_EX_DLL CCSkin : public CCSprite
{
protected:
    CCArmature *m_pArmature;
};
NS_CC_EXT_END
#endif
""",
            )
            w_extra(
                "extensions/CocoStudio/Armature/display/CCSkin.cpp",
                """#include "CCSkin.h"
NS_CC_EXT_BEGIN
void CCSkin::updateArmatureTransform()
{
    m_sTransform = CCAffineTransformConcat(m_tSkinTransform, m_pBone->nodeToArmatureTransform());
}
NS_CC_EXT_END
""",
            )
            w_extra(
                "extensions/CocoStudio/Armature/CCArmature.cpp",
                """#include "CCArmature.h"
NS_CC_EXT_BEGIN
void CCArmature::draw()
{
    switch (bone->getDisplayRenderNodeType())
    {
    case CS_DISPLAY_SPRITE:
    {
                CCSkin *skin = (CCSkin *)node;

                CCTextureAtlas *textureAtlas = skin->getTextureAtlas();

                ccBlendFunc func = bone->getBlendFunc();
                bool blendDirty = func.src != CC_BLEND_SRC || func.dst != CC_BLEND_DST;

                if(m_pAtlas != textureAtlas || blendDirty)
                {
                    if (m_pAtlas)
                    {
                        m_pAtlas->drawQuads();
                        m_pAtlas->removeAllQuads();
                    }
                }

                m_pAtlas = textureAtlas;
                if (m_pAtlas->getCapacity() == m_pAtlas->getTotalQuads() && !m_pAtlas->resizeCapacity(m_pAtlas->getCapacity() * 2))
                    return;

                skin->updateTransform();

                if (blendDirty)
                {
                    ccGLBlendFunc(func.src, func.dst);

                    m_pAtlas->drawQuads();
                    m_pAtlas->removeAllQuads();

                    ccGLBlendFunc(m_sBlendFunc.src, m_sBlendFunc.dst);
                }
    }
    break;
    case CS_DISPLAY_ARMATURE:
    {
                CCArmature *armature = (CCArmature *)(node);

                CCTextureAtlas *textureAtlas = armature->getTextureAtlas();
                if(m_pAtlas != textureAtlas)
                {
                    if (m_pAtlas)
                    {
                        m_pAtlas->drawQuads();
                        m_pAtlas->removeAllQuads();
                    }
                }
                armature->draw();

                m_pAtlas = armature->getTextureAtlas();
    }
    break;
    }
}
NS_CC_EXT_END
""",
            )

            self.assertEqual(patch_cocos2dx.main([str(cocos_root)]), 0)

            t2d = (cocos_root / "cocos2dx/textures/CCTexture2D.cpp").read_text(encoding="utf-8")
            self.assertIn("static bool PVRHaveAlphaPremultiplied_ = true;", t2d)
            self.assertIn("pvr->isForcePremultipliedAlpha()", t2d)

            pvr = (cocos_root / "cocos2dx/textures/CCTexturePVR.cpp").read_text(encoding="utf-8")
            self.assertIn("kPVR3TexturePixelFormat_R_8", pvr)
            self.assertIn("kPVR3TexturePixelFormat_RG_88", pvr)
            self.assertIn("GL_RGBA8", pvr)
            self.assertIn("case kCCTexture2DPixelFormat_RGBA4444:", pvr)
            self.assertIn("case kCCTexture2DPixelFormat_A8:", pvr)

            bone = (cocos_root / "extensions/CocoStudio/Armature/CCBone.cpp").read_text(encoding="utf-8")
            self.assertIn("if (r < 0) r = 0; else if (r > 255) r = 255;", bone)

            skin_h = (cocos_root / "extensions/CocoStudio/Armature/display/CCSkin.h").read_text(encoding="utf-8")
            skin_cpp = (cocos_root / "extensions/CocoStudio/Armature/display/CCSkin.cpp").read_text(encoding="utf-8")
            self.assertIn("virtual void setTextureCoords(CCRect rect);", skin_h)
            self.assertIn("void CCSkin::setTextureCoords(CCRect rect)", skin_cpp)
            self.assertIn("trimLeftPx <= 0.5f", skin_cpp)

            arm = (cocos_root / "extensions/CocoStudio/Armature/CCArmature.cpp").read_text(encoding="utf-8")
            self.assertIn("skin->isOpacityModifyRGB() ? GL_ONE : GL_SRC_ALPHA", arm)
            self.assertIn("childBlendDirty", arm)

            # Verify 100% idempotency on second run
            self.assertEqual(patch_cocos2dx.main([str(cocos_root)]), 0)
            self.assertEqual(pvr, (cocos_root / "cocos2dx/textures/CCTexturePVR.cpp").read_text(encoding="utf-8"))
            self.assertEqual(skin_cpp, (cocos_root / "extensions/CocoStudio/Armature/display/CCSkin.cpp").read_text(encoding="utf-8"))
            self.assertEqual(arm, (cocos_root / "extensions/CocoStudio/Armature/CCArmature.cpp").read_text(encoding="utf-8"))


class TestPeDependencyAuditor(unittest.TestCase):
    LUA_REQUIRED_EXPORTS = sorted(audit_pe.REQUIRED_LUA51_EXPORTS)

    def _populate_clean_release_dir(self, d: Path) -> str:
        lua_bytes = build_synthetic_pe(
            is_dll=True,
            imports={"KERNEL32.dll": ["VirtualAlloc"], "vcruntime140.dll": ["memcpy"], "api-ms-win-crt-runtime-l1-1-0.dll": ["_initterm"]},
            exports=self.LUA_REQUIRED_EXPORTS,
            pdb_path=r"D:\build\lua51.pdb",
            dll_name_for_export="lua51.dll",
        )
        lua_sha = hashlib.sha256(lua_bytes).hexdigest()
        (d / "lua51.dll").write_bytes(lua_bytes)

        (d / "zlib1.dll").write_bytes(
            build_synthetic_pe(
                is_dll=True,
                imports={"KERNEL32.dll": ["GetLastError"], "vcruntime140.dll": ["memset"]},
                exports=["inflate", "deflate"],
                pdb_path=r"D:\build\zlib1.pdb",
                dll_name_for_export="zlib1.dll",
            )
        )
        (d / "libcocos2d.dll").write_bytes(
            build_synthetic_pe(
                is_dll=True,
                imports={"KERNEL32.dll": ["QueryPerformanceCounter"], "zlib1.dll": ["inflate"], "vcruntime140.dll": ["memcpy"], "msvcp140.dll": ["?_Xout_of_range@std@@YAXPBD@Z"]},
                exports=["?sharedDirector@CCDirector@cocos2d@@SAPAV12@XZ"],
                pdb_path=r"D:\build\libcocos2d.pdb",
                dll_name_for_export="libcocos2d.dll",
            )
        )
        (d / "vcruntime140.dll").write_bytes(
            build_synthetic_pe(is_dll=True, imports={"KERNEL32.dll": ["GetProcAddress"]}, exports=["memcpy"])
        )
        (d / "msvcp140.dll").write_bytes(
            build_synthetic_pe(is_dll=True, imports={"KERNEL32.dll": ["GetProcAddress"], "vcruntime140.dll": ["memcpy"]}, exports=["?_Xout_of_range@std@@YAXPBD@Z"])
        )
        (d / "GCLIENT.exe").write_bytes(
            build_synthetic_pe(
                is_dll=False,
                imports={
                    "KERNEL32.dll": ["ExitProcess"],
                    "USER32.dll": ["CreateWindowExW"],
                    "libcocos2d.dll": ["?sharedDirector@CCDirector@cocos2d@@SAPAV12@XZ"],
                    "lua51.dll": ["luaL_newstate", "luaJIT_setmode"],
                    "zlib1.dll": ["inflate"],
                    "vcruntime140.dll": ["memcpy"],
                    "msvcp140.dll": ["?_Xout_of_range@std@@YAXPBD@Z"],
                },
                pdb_path=r"D:\build\GCLIENT.pdb",
                dll_name_for_export="GCLIENT.exe",
            )
        )
        return lua_sha

    def test_clean_pe32_closure_passes_and_emits_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rel = Path(tmp) / "gclient-win32-release"
            rel.mkdir()
            lua_sha = self._populate_clean_release_dir(rel)
            prov = Path(tmp) / "luajit-provenance.json"
            prov.write_text(json.dumps({"lua51_dll_sha256": lua_sha}), encoding="utf-8")

            rc = audit_pe.main(
                [
                    str(rel),
                    "--luajit-provenance",
                    str(prov),
                    "--require-app-local-vc-redist",
                    "--fail-on-unreferenced",
                ]
            )
            self.assertEqual(rc, 0)
            manifest = json.loads((rel / "dependency-manifest.json").read_text(encoding="utf-8"))
            self.assertTrue(manifest["passed"])
            self.assertEqual(manifest["violations"], [])
            self.assertTrue((rel / "SHA256SUMS.txt").is_file())

    def test_rejects_x64_msvcr100_debug_crt_missing_dep_and_bad_lua_sha(self) -> None:
        # 1. Rejects x64 PE32+ (0x8664) binary
        with tempfile.TemporaryDirectory() as tmp:
            rel = Path(tmp) / "x64_contaminated"
            rel.mkdir()
            self._populate_clean_release_dir(rel)
            (rel / "zlib1.dll").write_bytes(
                build_synthetic_pe(is_dll=True, is_64bit=True, imports={"KERNEL32.dll": ["Sleep"]})
            )
            self.assertEqual(audit_pe.main([str(rel)]), 1)

        # 2. Rejects MSVCR100.dll even when hidden in Delay-Load Import Directory!
        with tempfile.TemporaryDirectory() as tmp:
            rel = Path(tmp) / "msvcr100_delay"
            rel.mkdir()
            self._populate_clean_release_dir(rel)
            (rel / "lua51.dll").write_bytes(
                build_synthetic_pe(
                    is_dll=True,
                    imports={"KERNEL32.dll": ["VirtualAlloc"]},
                    delay_imports={"MSVCR100.dll": ["malloc"]},
                    exports=self.LUA_REQUIRED_EXPORTS,
                )
            )
            self.assertEqual(audit_pe.main([str(rel)]), 1)

        # 3. Rejects Debug CRT (vcruntime140d.dll / ucrtbased.dll)
        with tempfile.TemporaryDirectory() as tmp:
            rel = Path(tmp) / "debug_crt"
            rel.mkdir()
            self._populate_clean_release_dir(rel)
            (rel / "zlib1.dll").write_bytes(
                build_synthetic_pe(is_dll=True, imports={"vcruntime140d.dll": ["memcpy"], "ucrtbased.dll": ["malloc"]})
            )
            self.assertEqual(audit_pe.main([str(rel)]), 1)

        # 4. Rejects missing non-OS transitive DLL
        with tempfile.TemporaryDirectory() as tmp:
            rel = Path(tmp) / "missing_dll"
            rel.mkdir()
            self._populate_clean_release_dir(rel)
            (rel / "zlib1.dll").unlink()
            self.assertEqual(audit_pe.main([str(rel)]), 1)

        # 5. Rejects stale lua51.dll SHA-256 mismatch
        with tempfile.TemporaryDirectory() as tmp:
            rel = Path(tmp) / "stale_sha"
            rel.mkdir()
            self._populate_clean_release_dir(rel)
            self.assertEqual(audit_pe.main([str(rel), "--expected-lua51-sha256", "a" * 64]), 1)

    def test_bfs_transitive_stager_excludes_dead_unreferenced_dlls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pool = Path(tmp) / "pool"
            pool.mkdir()
            lua_sha = self._populate_clean_release_dir(pool)
            for name in ("GCLIENT", "libcocos2d", "lua51", "zlib1"):
                (pool / f"{name}.pdb").write_bytes(b"PDB_SYMBOLS")
            # Dead legacy DLL sitting in build folder — must NOT be copied into staged output!
            (pool / "libtiff.dll").write_bytes(
                build_synthetic_pe(is_dll=True, imports={"MSVCR100.dll": ["malloc"]})
            )

            staged_dir = Path(tmp) / "dist_release"
            pdb_dir = Path(tmp) / "dist_symbols"
            rc = audit_pe.main(
                [
                    str(staged_dir),
                    "--stage-from-root-exe",
                    str(pool / "GCLIENT.exe"),
                    "--search-dir",
                    str(pool),
                    "--pdb-output-dir",
                    str(pdb_dir),
                    "--expected-lua51-sha256",
                    lua_sha,
                    "--require-app-local-vc-redist",
                    "--fail-on-unreferenced",
                ]
            )
            self.assertEqual(rc, 0)
            self.assertFalse((staged_dir / "libtiff.dll").exists())
            self.assertTrue((pdb_dir / "GCLIENT.pdb").is_file())
            self.assertTrue((pdb_dir / "lua51.pdb").is_file())


class TestResourceValidatorUnicodeAndSqlite(unittest.TestCase):
    def test_unicode_sqlite_uri_and_encrypted_db_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            res_root = Path(tmp) / "Resources Tiếng Việt #1"
            db_dir = res_root / "db"
            (res_root / "script").mkdir(parents=True)
            db_dir.mkdir(parents=True)

            # Create valid SQLite DB inside path containing spaces, '#', and Vietnamese characters
            good_db = db_dir / "DB_Hero_Config.db"
            conn = sqlite3.connect(str(good_db))
            conn.execute("CREATE TABLE Hero(id INTEGER PRIMARY KEY, name TEXT);")
            conn.execute("INSERT INTO Hero VALUES(1, 'Kestrel');")
            conn.commit()
            conn.close()

            from collections import Counter
            stats_good = validate_resources.DbStats()
            validate_resources.audit_db_file(
                good_db, "db/DB_Hero_Config.db", 5, stats_good, Counter(), []
            )
            self.assertEqual(stats_good.valid_sqlite3, 1, stats_good.error_samples)
            self.assertEqual(stats_good.open_or_query_errors, 0, stats_good.error_samples)

            # Raw 0xFEFEFEFE encrypted DB must be rejected with clear diagnostic
            enc_db = db_dir / "DB_Encrypted.db"
            enc_db.write_bytes(b"\xfe\xfe\xfe\xfe" + b"\x00" * 60)
            stats_enc = validate_resources.DbStats()
            validate_resources.audit_db_file(
                enc_db, "db/DB_Encrypted.db", 5, stats_enc, Counter(), []
            )
            self.assertEqual(stats_enc.bt_encrypted_file, 1)
            self.assertTrue(any("0xFEFEFEFE" in s for s in stats_enc.error_samples))

            # Verify 32-byte 0xFEFEFEFE header reads keyIndex from byte[9], NOT payloadSize[4]!
            hdr32 = bytearray(32)
            hdr32[0:4] = b"\xfe\xfe\xfe\xfe"
            hdr32[4:8] = (200).to_bytes(4, "little")  # payloadSize low byte = 200 (>= 16!)
            hdr32[8] = 0                              # algoIndex = 0
            hdr32[9] = 7                              # keyIndex = 7 (< 16)
            self.assertEqual(validate_resources.parse_bt_key_index(bytes(hdr32)), 7)
            is_enc, hex_key = validate_resources.try_decode_hex_fefefefe(bytes(hdr32).hex())
            self.assertTrue(is_enc)
            self.assertEqual(hex_key, 7)


if __name__ == "__main__":
    unittest.main(verbosity=2)
