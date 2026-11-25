#!/usr/bin/env python3
"""
tools/audit_pe_dependencies.py — Zero-Dependency Win32 PE32/PE32+ Recursive Dependency,
CRT Hygiene, ABI Architecture, Manifest & LuaJIT Provenance Gate for gclient-win32-release.

Capabilities:
  1. Deterministic BFS transitive runtime DLL stager (`--stage-from-root-exe` + `--search-dir`)
     so dead/unreferenced DLLs never pollute `gclient-win32-release`.
  2. Pure-Python `struct` parser for PE32 (`0x10B`) & PE32+ (`0x20B`) COFF headers, Optional
     headers, Section headers, Import Directory (`idx 1`), Delay-Load Import Directory (`idx 13`),
     Export Directory (`idx 0`), Debug Directory (`idx 6` RSDS CodeView `.pdb`), and Resource
     Directory (`RT_MANIFEST` embedded side-by-side XML).
  3. Cross-checks `dumpbin.exe /headers /dependents` on Windows when available.
  4. Fails CI (exit code 1) if ANY of the following occur:
       - Any binary is not 32-bit x86 (`IMAGE_FILE_MACHINE_I386` / `0x014C`), e.g. x64 `0x8664`
       - Any prohibited legacy CRT (`MSVCR80..120.dll`, `MSVCP80..120.dll`) appears
       - Any Debug or ASan runtime (`*140D.dll`, `UCRTBASED.dll`, `MSVCR*D.dll`, `*asan*`) appears
       - Any non-OS imported DLL is missing from the artifact directory
       - Mandatory binaries (`GCLIENT.exe`, `libcocos2d.dll`, `lua51.dll`) or required Lua 5.1 /
         LuaJIT C API exports (`luaL_newstate`, `luaJIT_setmode`, etc.) are missing
       - `lua51.dll` SHA-256 does not match the freshly built LuaJIT 2.0.1 provenance record
  5. Writes machine-readable `dependency-manifest.json` and `SHA256SUMS.txt`.
"""

from __future__ import annotations

import argparse
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import sys
from typing import Dict, List, Optional, Sequence, Set, Tuple

DOS_MAGIC_MZ = 0x5A4D
PE_SIGNATURE = 0x00004550

IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_ARM64 = 0xAA64

IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020
IMAGE_FILE_DLL = 0x2000

PE_OPTIONAL_HDR32_MAGIC = 0x010B
PE_OPTIONAL_HDR64_MAGIC = 0x020B

IMAGE_DIRECTORY_ENTRY_EXPORT = 0
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_RESOURCE = 2
IMAGE_DIRECTORY_ENTRY_DEBUG = 6
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13

MACHINE_NAMES: Dict[int, str] = {
    IMAGE_FILE_MACHINE_I386: "IMAGE_FILE_MACHINE_I386",
    IMAGE_FILE_MACHINE_AMD64: "IMAGE_FILE_MACHINE_AMD64",
    IMAGE_FILE_MACHINE_ARM64: "IMAGE_FILE_MACHINE_ARM64",
}

PROHIBITED_LEGACY_CRTS: Set[str] = {
    "msvcr70.dll",
    "msvcr71.dll",
    "msvcr80.dll",
    "msvcp80.dll",
    "msvcm80.dll",
    "msvcr90.dll",
    "msvcp90.dll",
    "msvcm90.dll",
    "msvcr100.dll",
    "msvcp100.dll",
    "msvcr100_clr0400.dll",
    "msvcr110.dll",
    "msvcp110.dll",
    "msvcr120.dll",
    "msvcp120.dll",
}

PROHIBITED_LEGACY_THIRD_PARTY_DLLS: Set[str] = {
    "pthreadvce2.dll",
    "ssleay32.dll",
    "libeay32.dll",
    "libtiff.dll",
    "websockets.dll",
}

DEBUG_OR_SANITIZER_DLL_PATTERNS: Tuple[re.Pattern[str], ...] = (
    re.compile(r"^vcruntime140_?\d*d\.dll$", re.IGNORECASE),
    re.compile(r"^msvcp140_?\d*d\.dll$", re.IGNORECASE),
    re.compile(r"^concrt140d\.dll$", re.IGNORECASE),
    re.compile(r"^vccorlib140d\.dll$", re.IGNORECASE),
    re.compile(r"^ucrtbased\.dll$", re.IGNORECASE),
    re.compile(r"^msvcr\d+d\.dll$", re.IGNORECASE),
    re.compile(r"^msvcp\d+d\.dll$", re.IGNORECASE),
    re.compile(r".*asan.*\.dll$", re.IGNORECASE),
)

MODERN_REDIST_CRT_DLLS: Set[str] = {
    "vcruntime140.dll",
    "vcruntime140_1.dll",
    "msvcp140.dll",
    "msvcp140_1.dll",
    "msvcp140_2.dll",
    "msvcp140_atomic_wait.dll",
    "msvcp140_codecvt_ids.dll",
    "concrt140.dll",
    "vccorlib140.dll",
}

WINDOWS_INBOX_OS_DLLS: Set[str] = {
    "ntdll.dll",
    "kernel32.dll",
    "kernelbase.dll",
    "user32.dll",
    "gdi32.dll",
    "gdiplus.dll",
    "opengl32.dll",
    "glu32.dll",
    "winmm.dll",
    "ws2_32.dll",
    "wsock32.dll",
    "mswsock.dll",
    "iphlpapi.dll",
    "dnsapi.dll",
    "winhttp.dll",
    "wininet.dll",
    "advapi32.dll",
    "sechost.dll",
    "shell32.dll",
    "shlwapi.dll",
    "shcore.dll",
    "comdlg32.dll",
    "comctl32.dll",
    "ole32.dll",
    "oleaut32.dll",
    "rpcrt4.dll",
    "crypt32.dll",
    "bcrypt.dll",
    "bcryptprimitives.dll",
    "ncrypt.dll",
    "wldap32.dll",
    "normaliz.dll",
    "secur32.dll",
    "sspicli.dll",
    "dbghelp.dll",
    "dbgcore.dll",
    "psapi.dll",
    "version.dll",
    "imm32.dll",
    "uxtheme.dll",
    "dwmapi.dll",
    "setupapi.dll",
    "cfgmgr32.dll",
    "userenv.dll",
    "profapi.dll",
    "powrprof.dll",
    "msvcrt.dll",
    "ucrtbase.dll",
}

REQUIRED_LUA51_EXPORTS: Tuple[str, ...] = (
    "luaL_newstate",
    "luaL_openlibs",
    "luaL_loadbuffer",
    "luaL_loadstring",
    "luaL_ref",
    "luaL_unref",
    "lua_close",
    "lua_pcall",
    "lua_cpcall",
    "lua_call",
    "lua_pushcclosure",
    "lua_pushlstring",
    "lua_tolstring",
    "lua_tonumber",
    "lua_tointeger",
    "lua_createtable",
    "lua_getfield",
    "lua_setfield",
    "lua_newuserdata",
    "lua_setmetatable",
    "lua_getstack",
    "lua_getinfo",
    "lua_gc",
    "luaJIT_setmode",
)


@dataclass
class SectionInfo:
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_offset: int


@dataclass
class ImportedModuleInfo:
    dll_name: str
    classification: str
    delay_loaded: bool
    imported_symbol_count: int
    sample_symbols: List[str] = field(default_factory=list)


@dataclass
class BinaryAuditEntry:
    filename: str
    relative_path: str
    size_bytes: int
    sha256: str
    machine: int
    machine_name: str
    pe_format: str
    is_dll: bool
    large_address_aware: bool
    subsystem: int
    linker_version: str
    os_version: str
    pdb_path: str
    has_embedded_manifest: bool
    sxs_dependencies: List[str] = field(default_factory=list)
    direct_imports: List[ImportedModuleInfo] = field(default_factory=list)
    delay_imports: List[ImportedModuleInfo] = field(default_factory=list)
    export_count: int = 0
    sample_exports: List[str] = field(default_factory=list)


@dataclass
class AuditManifest:
    generated_at_utc: str
    artifact_dir: str
    root_executable: str
    total_binaries: int
    transitive_closure_shipped: List[str]
    transitive_os_dependencies: List[str]
    vc_redist_crt_dependencies: List[str]
    missing_dependencies: List[str]
    unreferenced_staged_binaries: List[str]
    violations: List[str]
    passed: bool
    binaries: List[BinaryAuditEntry]


def classify_dll(name: str) -> str:
    low = name.lower()
    if low in PROHIBITED_LEGACY_CRTS:
        return "PROHIBITED_LEGACY_CRT"
    if low in PROHIBITED_LEGACY_THIRD_PARTY_DLLS:
        return "PROHIBITED_LEGACY_3RDPARTY"
    for pat in DEBUG_OR_SANITIZER_DLL_PATTERNS:
        if pat.match(low):
            return "PROHIBITED_DEBUG_OR_SANITIZER_CRT"
    if low.startswith("api-ms-win-") or low.startswith("ext-ms-"):
        return "WINDOWS_API_SET"
    if low in WINDOWS_INBOX_OS_DLLS:
        return "WINDOWS_OS_SYSTEM"
    if low in MODERN_REDIST_CRT_DLLS:
        return "MODERN_VC143_REDIST_CRT"
    return "APPLICATION_OR_3RDPARTY"


def is_os_provided_dll(classification: str) -> bool:
    return classification in ("WINDOWS_API_SET", "WINDOWS_OS_SYSTEM")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def rva_to_offset(rva: int, sections: Sequence[SectionInfo], file_len: int) -> Optional[int]:
    if rva == 0:
        return None
    for s in sections:
        span = max(s.virtual_size, s.raw_size)
        if s.virtual_address <= rva < s.virtual_address + span:
            off = s.raw_offset + (rva - s.virtual_address)
            if 0 <= off < file_len:
                return off
    return None


def read_c_string(data: bytes, offset: Optional[int], max_len: int = 512) -> str:
    if offset is None or offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset, min(len(data), offset + max_len))
    if end == -1:
        end = min(len(data), offset + max_len)
    return data[offset:end].decode("ascii", errors="replace")


def _parse_import_thunks(
    data: bytes,
    thunk_rva: int,
    is_pe32_plus: bool,
    sections: Sequence[SectionInfo],
) -> Tuple[int, List[str]]:
    off = rva_to_offset(thunk_rva, sections, len(data))
    if off is None:
        return 0, []
    entry_size = 8 if is_pe32_plus else 4
    ordinal_flag = (1 << 63) if is_pe32_plus else (1 << 31)
    fmt = "<Q" if is_pe32_plus else "<I"
    count = 0
    samples: List[str] = []
    while off + entry_size <= len(data):
        (val,) = struct.unpack_from(fmt, data, off)
        off += entry_size
        if val == 0:
            break
        count += 1
        if len(samples) < 12:
            if val & ordinal_flag:
                samples.append(f"#{val & 0xFFFF}")
            else:
                hint_name_off = rva_to_offset(val & 0x7FFFFFFF, sections, len(data))
                if hint_name_off is not None and hint_name_off + 2 < len(data):
                    sym = read_c_string(data, hint_name_off + 2)
                    if sym:
                        samples.append(sym)
    return count, samples


def _extract_sxs_manifest_info(data: bytes) -> Tuple[bool, List[str]]:
    """Detect embedded XML manifest and extract any <assemblyIdentity name='...'/> dependencies."""
    idx = data.find(b"<assembly")
    if idx == -1:
        return False, []
    end = data.find(b"</assembly>", idx)
    if end == -1:
        return True, []
    xml_bytes = data[idx : end + len(b"</assembly>")]
    xml_txt = xml_bytes.decode("utf-8", errors="ignore")
    deps: List[str] = []
    for dep_block in re.findall(r"<dependentAssembly>(.*?)</dependentAssembly>", xml_txt, flags=re.DOTALL):
        m = re.search(r'assemblyIdentity[^>]*?\bname\s*=\s*["\']([^"\']+)["\']', dep_block)
        if m:
            deps.append(m.group(1))
    return True, deps


def parse_pe_file(path: Path, root_dir: Path) -> Tuple[BinaryAuditEntry, Set[str]]:
    data = path.read_bytes()
    if len(data) < 64:
        raise ValueError(f"{path.name}: file too small to be a valid PE image ({len(data)} bytes)")
    (mz_magic,) = struct.unpack_from("<H", data, 0)
    if mz_magic != DOS_MAGIC_MZ:
        raise ValueError(f"{path.name}: missing MZ signature (0x{mz_magic:04X})")
    (pe_off,) = struct.unpack_from("<I", data, 0x3C)
    if pe_off + 24 > len(data):
        raise ValueError(f"{path.name}: invalid e_lfanew offset 0x{pe_off:X}")
    (pe_sig,) = struct.unpack_from("<I", data, pe_off)
    if pe_sig != PE_SIGNATURE:
        raise ValueError(f"{path.name}: missing PE\\0\\0 signature")

    machine, num_sections, _, _, _, opt_hdr_size, characteristics = struct.unpack_from(
        "<HHIIIHH", data, pe_off + 4
    )
    opt_off = pe_off + 24
    if opt_off + opt_hdr_size > len(data) or opt_hdr_size < 24:
        raise ValueError(f"{path.name}: truncated Optional Header")

    (opt_magic,) = struct.unpack_from("<H", data, opt_off)
    if opt_magic == PE_OPTIONAL_HDR32_MAGIC:
        is_pe32_plus = False
        pe_fmt = "PE32"
        maj_link, min_link = struct.unpack_from("<BB", data, opt_off + 2)
        (image_base,) = struct.unpack_from("<I", data, opt_off + 28)
        maj_os, min_os = struct.unpack_from("<HH", data, opt_off + 40)
        (subsystem,) = struct.unpack_from("<H", data, opt_off + 68)
        (num_rva_sizes,) = struct.unpack_from("<I", data, opt_off + 92)
        dd_off = opt_off + 96
    elif opt_magic == PE_OPTIONAL_HDR64_MAGIC:
        is_pe32_plus = True
        pe_fmt = "PE32+"
        maj_link, min_link = struct.unpack_from("<BB", data, opt_off + 2)
        (image_base,) = struct.unpack_from("<Q", data, opt_off + 24)
        maj_os, min_os = struct.unpack_from("<HH", data, opt_off + 40)
        (subsystem,) = struct.unpack_from("<H", data, opt_off + 68)
        (num_rva_sizes,) = struct.unpack_from("<I", data, opt_off + 108)
        dd_off = opt_off + 112
    else:
        raise ValueError(f"{path.name}: unsupported Optional Header magic 0x{opt_magic:04X}")

    data_dirs: List[Tuple[int, int]] = []
    max_dirs = min(num_rva_sizes, (opt_off + opt_hdr_size - dd_off) // 8)
    for i in range(max_dirs):
        rva, sz = struct.unpack_from("<II", data, dd_off + i * 8)
        data_dirs.append((rva, sz))

    sec_off = opt_off + opt_hdr_size
    sections: List[SectionInfo] = []
    for i in range(num_sections):
        pos = sec_off + i * 40
        if pos + 40 > len(data):
            break
        raw_name, vsize, vaddr, rsize, roff = struct.unpack_from("<8sIIII", data, pos)
        sec_name = raw_name.split(b"\x00", 1)[0].decode("ascii", errors="replace")
        sections.append(SectionInfo(sec_name, vsize, vaddr, rsize, roff))

    # 1. Standard Import Directory (idx 1)
    direct_imports: List[ImportedModuleInfo] = []
    if len(data_dirs) > IMAGE_DIRECTORY_ENTRY_IMPORT:
        imp_rva, imp_sz = data_dirs[IMAGE_DIRECTORY_ENTRY_IMPORT]
        imp_off = rva_to_offset(imp_rva, sections, len(data))
        if imp_rva != 0 and imp_off is not None:
            cur = imp_off
            while cur + 20 <= len(data):
                orig_first_thunk, _, _, name_rva, first_thunk = struct.unpack_from("<IIIII", data, cur)
                cur += 20
                if orig_first_thunk == 0 and name_rva == 0 and first_thunk == 0:
                    break
                dll_name = read_c_string(data, rva_to_offset(name_rva, sections, len(data)))
                if not dll_name:
                    continue
                thunk_rva = orig_first_thunk if orig_first_thunk != 0 else first_thunk
                sym_count, samples = _parse_import_thunks(data, thunk_rva, is_pe32_plus, sections)
                direct_imports.append(
                    ImportedModuleInfo(
                        dll_name=dll_name,
                        classification=classify_dll(dll_name),
                        delay_loaded=False,
                        imported_symbol_count=sym_count,
                        sample_symbols=samples,
                    )
                )

    # 2. Delay-Load Import Directory (idx 13)
    delay_imports: List[ImportedModuleInfo] = []
    if len(data_dirs) > IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:
        del_rva, _ = data_dirs[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]
        del_off = rva_to_offset(del_rva, sections, len(data))
        if del_rva != 0 and del_off is not None:
            cur = del_off
            while cur + 32 <= len(data):
                attrs, name_rva, _, _, int_rva, _, _, _ = struct.unpack_from("<IIIIIIII", data, cur)
                cur += 32
                if name_rva == 0 and int_rva == 0:
                    break
                is_rva_mode = (attrs & 1) != 0 or name_rva < image_base
                eff_name_rva = name_rva if is_rva_mode else (name_rva - image_base)
                eff_int_rva = int_rva if is_rva_mode else (int_rva - image_base if int_rva >= image_base else 0)
                dll_name = read_c_string(data, rva_to_offset(eff_name_rva, sections, len(data)))
                if not dll_name:
                    continue
                sym_count, samples = _parse_import_thunks(data, eff_int_rva, is_pe32_plus, sections)
                delay_imports.append(
                    ImportedModuleInfo(
                        dll_name=dll_name,
                        classification=classify_dll(dll_name),
                        delay_loaded=True,
                        imported_symbol_count=sym_count,
                        sample_symbols=samples,
                    )
                )

    # 3. Export Directory (idx 0)
    all_exports: Set[str] = set()
    sample_exports: List[str] = []
    export_count = 0
    if len(data_dirs) > IMAGE_DIRECTORY_ENTRY_EXPORT:
        exp_rva, _ = data_dirs[IMAGE_DIRECTORY_ENTRY_EXPORT]
        exp_off = rva_to_offset(exp_rva, sections, len(data))
        if exp_rva != 0 and exp_off is not None and exp_off + 40 <= len(data):
            _, _, _, _, _, num_funcs, num_names, _, names_rva, _ = struct.unpack_from("<IIIIIIIIII", data, exp_off)
            export_count = max(num_funcs, num_names)
            names_off = rva_to_offset(names_rva, sections, len(data))
            if names_off is not None:
                for i in range(num_names):
                    if names_off + (i + 1) * 4 > len(data):
                        break
                    (fn_name_rva,) = struct.unpack_from("<I", data, names_off + i * 4)
                    fn_name = read_c_string(data, rva_to_offset(fn_name_rva, sections, len(data)))
                    if fn_name:
                        all_exports.add(fn_name)
                        if len(sample_exports) < 25:
                            sample_exports.append(fn_name)

    # 4. Debug Directory (idx 6 — RSDS CodeView PDB record)
    pdb_path = ""
    if len(data_dirs) > IMAGE_DIRECTORY_ENTRY_DEBUG:
        dbg_rva, dbg_sz = data_dirs[IMAGE_DIRECTORY_ENTRY_DEBUG]
        dbg_off = rva_to_offset(dbg_rva, sections, len(data))
        if dbg_rva != 0 and dbg_off is not None:
            num_dbg = dbg_sz // 28
            for i in range(num_dbg):
                pos = dbg_off + i * 28
                if pos + 28 > len(data):
                    break
                _, _, _, dbg_type, size_of_data, _, ptr_raw = struct.unpack_from("<IIHHIII", data, pos)
                if dbg_type == 2 and ptr_raw + 24 < len(data) and size_of_data >= 24:
                    if data[ptr_raw : ptr_raw + 4] == b"RSDS":
                        end = data.find(b"\x00", ptr_raw + 24, min(len(data), ptr_raw + size_of_data))
                        if end == -1:
                            end = min(len(data), ptr_raw + size_of_data)
                        pdb_path = data[ptr_raw + 24 : end].decode("utf-8", errors="replace")
                        break

    has_manifest, sxs_deps = _extract_sxs_manifest_info(data)
    rel = str(path.relative_to(root_dir)).replace("\\", "/")

    entry = BinaryAuditEntry(
        filename=path.name,
        relative_path=rel,
        size_bytes=len(data),
        sha256=sha256_file(path),
        machine=machine,
        machine_name=MACHINE_NAMES.get(machine, f"0x{machine:04X}"),
        pe_format=pe_fmt,
        is_dll=bool(characteristics & IMAGE_FILE_DLL),
        large_address_aware=bool(characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE),
        subsystem=subsystem,
        linker_version=f"{maj_link}.{min_link}",
        os_version=f"{maj_os}.{min_os}",
        pdb_path=pdb_path,
        has_embedded_manifest=has_manifest,
        sxs_dependencies=sxs_deps,
        direct_imports=direct_imports,
        delay_imports=delay_imports,
        export_count=export_count,
        sample_exports=sample_exports,
    )
    return entry, all_exports


def stage_transitive_closure(
    root_exe: Path,
    dest_dir: Path,
    search_dirs: Sequence[Path],
    pdb_dest_dir: Optional[Path] = None,
) -> List[str]:
    """Deterministically copy root_exe and ONLY its transitive non-OS DLL closure into dest_dir."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    if pdb_dest_dir is not None:
        pdb_dest_dir.mkdir(parents=True, exist_ok=True)

    # Index available DLLs and PDBs across search_dirs in priority order
    dll_index: Dict[str, Path] = {}
    pdb_index: Dict[str, Path] = {}
    all_dirs = [root_exe.parent] + list(search_dirs)
    for sdir in all_dirs:
        if not sdir.is_dir():
            continue
        for item in sdir.iterdir():
            if not item.is_file():
                continue
            low = item.name.lower()
            if low.endswith(".dll") and low not in dll_index:
                dll_index[low] = item
            elif low.endswith(".pdb") and low not in pdb_index:
                pdb_index[low] = item

    staged: List[str] = []
    visited: Set[str] = set()
    queue: deque[Path] = deque([root_exe])

    shutil.copy2(root_exe, dest_dir / root_exe.name)
    staged.append(root_exe.name)
    visited.add(root_exe.name.lower())

    exe_pdb = root_exe.with_suffix(".pdb")
    if pdb_dest_dir is not None and exe_pdb.is_file():
        shutil.copy2(exe_pdb, pdb_dest_dir / exe_pdb.name)

    while queue:
        cur_bin = queue.popleft()
        entry, _ = parse_pe_file(cur_bin, cur_bin.parent)
        for imp in entry.direct_imports + entry.delay_imports:
            cls = imp.classification
            if is_os_provided_dll(cls):
                continue
            low_dll = imp.dll_name.lower()
            if low_dll in visited:
                continue
            if low_dll in dll_index:
                src_dll = dll_index[low_dll]
                dst_dll = dest_dir / src_dll.name
                shutil.copy2(src_dll, dst_dll)
                staged.append(src_dll.name)
                visited.add(low_dll)
                queue.append(dst_dll)

                if pdb_dest_dir is not None:
                    pdb_key = src_dll.with_suffix(".pdb").name.lower()
                    if pdb_key in pdb_index:
                        shutil.copy2(pdb_index[pdb_key], pdb_dest_dir / pdb_index[pdb_key].name)

    return staged


def cross_check_with_dumpbin(dumpbin_exe: str, bin_path: Path) -> List[str]:
    """Optional cross-check with MSVC dumpbin.exe on Windows runners."""
    issues: List[str] = []
    proc = subprocess.run(
        [dumpbin_exe, "/headers", "/dependents", str(bin_path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if proc.returncode != 0:
        issues.append(f"dumpbin exited with code {proc.returncode} on {bin_path.name}")
        return issues
    if "14C machine (x86)" not in proc.stdout:
        issues.append(f"dumpbin /headers did not report 14C machine (x86) for {bin_path.name}")
    return issues


def audit_artifact_directory(
    artifact_dir: Path,
    root_exe_name: str = "GCLIENT.exe",
    expected_lua51_sha256: str = "",
    allow_system_vc_redist: bool = True,
    dumpbin_exe: str = "",
) -> AuditManifest:
    pe_files: List[Path] = sorted(
        [
            p
            for p in artifact_dir.rglob("*")
            if p.is_file() and p.suffix.lower() in (".exe", ".dll")
        ],
        key=lambda p: p.name.lower(),
    )

    by_lower: Dict[str, BinaryAuditEntry] = {}
    exports_by_lower: Dict[str, Set[str]] = {}
    entries: List[BinaryAuditEntry] = []
    violations: List[str] = []

    for p in pe_files:
        try:
            entry, exps = parse_pe_file(p, artifact_dir)
        except Exception as exc:
            violations.append(f"Malformed PE binary '{p.name}': {exc}")
            continue
        entries.append(entry)
        by_lower[p.name.lower()] = entry
        exports_by_lower[p.name.lower()] = exps

        if entry.machine != IMAGE_FILE_MACHINE_I386 or entry.pe_format != "PE32":
            violations.append(
                f"Architecture violation in '{entry.relative_path}': got {entry.machine_name} ({entry.pe_format}), "
                "expected IMAGE_FILE_MACHINE_I386 (PE32 x86)"
            )

        low_self = entry.filename.lower()
        if low_self in PROHIBITED_LEGACY_CRTS or low_self in PROHIBITED_LEGACY_THIRD_PARTY_DLLS:
            violations.append(f"Prohibited legacy binary shipped in artifact: '{entry.relative_path}'")
        for pat in DEBUG_OR_SANITIZER_DLL_PATTERNS:
            if pat.match(low_self):
                violations.append(f"Debug/Sanitizer runtime shipped in Release artifact: '{entry.relative_path}'")

        for sxs in entry.sxs_dependencies:
            if any(tok in sxs.lower() for tok in ("vc80", "vc90", "vc100", "debugcrt")):
                violations.append(f"Obsolete/Debug Side-by-Side manifest dependency '{sxs}' in '{entry.relative_path}'")

        for imp in entry.direct_imports + entry.delay_imports:
            if imp.classification == "PROHIBITED_LEGACY_CRT":
                violations.append(
                    f"Legacy CRT dependency '{imp.dll_name}' imported by '{entry.relative_path}'"
                )
            elif imp.classification == "PROHIBITED_LEGACY_3RDPARTY":
                violations.append(
                    f"Obsolete 3rd-party DLL '{imp.dll_name}' imported by '{entry.relative_path}'"
                )
            elif imp.classification == "PROHIBITED_DEBUG_OR_SANITIZER_CRT":
                violations.append(
                    f"Debug/Sanitizer CRT '{imp.dll_name}' imported by '{entry.relative_path}'"
                )

        if dumpbin_exe and platform.system().lower().startswith("win"):
            violations.extend(cross_check_with_dumpbin(dumpbin_exe, p))

    # Mandatory binary checks
    for mandatory in (root_exe_name, "libcocos2d.dll", "lua51.dll"):
        if mandatory.lower() not in by_lower:
            violations.append(f"Mandatory binary missing from artifact: '{mandatory}'")

    root_entry = by_lower.get(root_exe_name.lower())
    if root_entry and not root_entry.large_address_aware:
        violations.append(f"'{root_exe_name}' is missing /LARGEADDRESSAWARE flag")

    # LuaJIT 2.0.1 export & provenance check
    lua_entry = by_lower.get("lua51.dll")
    if lua_entry is not None:
        lua_exps = exports_by_lower.get("lua51.dll", set())
        missing_lua_syms = [s for s in REQUIRED_LUA51_EXPORTS if s not in lua_exps]
        if missing_lua_syms:
            violations.append(
                f"lua51.dll is missing {len(missing_lua_syms)} required Lua 5.1 / LuaJIT exports: "
                + ", ".join(missing_lua_syms[:10])
            )
        if expected_lua51_sha256 and lua_entry.sha256.lower() != expected_lua51_sha256.strip().lower():
            violations.append(
                f"Stale lua51.dll provenance! Artifact SHA-256={lua_entry.sha256} != "
                f"freshly compiled LuaJIT SHA-256={expected_lua51_sha256.strip().lower()}"
            )

    # Transitive BFS closure from root_exe_name
    reachable_shipped: Set[str] = set()
    os_deps: Set[str] = set()
    vc_redist_deps: Set[str] = set()
    missing_deps: Set[str] = set()

    if root_exe_name.lower() in by_lower:
        bfs: deque[str] = deque([root_exe_name.lower()])
        reachable_shipped.add(by_lower[root_exe_name.lower()].filename)
        visited_low: Set[str] = {root_exe_name.lower()}

        while bfs:
            cur_low = bfs.popleft()
            cur_ent = by_lower[cur_low]
            for imp in cur_ent.direct_imports + cur_ent.delay_imports:
                imp_low = imp.dll_name.lower()
                cls = imp.classification
                if is_os_provided_dll(cls):
                    os_deps.add(imp.dll_name)
                    continue
                if cls == "MODERN_VC143_REDIST_CRT":
                    vc_redist_deps.add(imp.dll_name)
                    if imp_low in by_lower:
                        reachable_shipped.add(by_lower[imp_low].filename)
                        if imp_low not in visited_low:
                            visited_low.add(imp_low)
                            bfs.append(imp_low)
                    elif not allow_system_vc_redist:
                        missing_deps.add(f"{imp.dll_name} (imported by {cur_ent.filename})")
                    continue

                if imp_low in by_lower:
                    reachable_shipped.add(by_lower[imp_low].filename)
                    if imp_low not in visited_low:
                        visited_low.add(imp_low)
                        bfs.append(imp_low)
                else:
                    missing_deps.add(f"{imp.dll_name} (imported by {cur_ent.filename})")

    for m in sorted(missing_deps):
        violations.append(f"Missing required runtime DLL dependency: {m}")

    unreferenced = sorted(
        [e.filename for e in entries if e.filename not in reachable_shipped],
        key=str.lower,
    )

    return AuditManifest(
        generated_at_utc=datetime.now(timezone.utc).isoformat(),
        artifact_dir=str(artifact_dir),
        root_executable=root_exe_name,
        total_binaries=len(entries),
        transitive_closure_shipped=sorted(reachable_shipped, key=str.lower),
        transitive_os_dependencies=sorted(os_deps, key=str.lower),
        vc_redist_crt_dependencies=sorted(vc_redist_deps, key=str.lower),
        missing_dependencies=sorted(missing_deps, key=str.lower),
        unreferenced_staged_binaries=unreferenced,
        violations=violations,
        passed=(len(violations) == 0),
        binaries=entries,
    )


def write_sha256_sums(directory: Path, out_file: Path) -> None:
    lines: List[str] = []
    for p in sorted(directory.rglob("*"), key=lambda x: str(x).lower()):
        if not p.is_file() or p.resolve() == out_file.resolve():
            continue
        rel = str(p.relative_to(directory)).replace("\\", "/")
        lines.append(f"{sha256_file(p)}  {rel}")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8", newline="\n")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Stage and recursively audit PE32 dependencies, CRTs, and LuaJIT exports."
    )
    parser.add_argument("artifact_dir", type=Path, help="Staging or release artifact directory to audit.")
    parser.add_argument("--root-exe", default="GCLIENT.exe", help="Root executable filename (default: GCLIENT.exe).")
    parser.add_argument(
        "--stage-from-root-exe",
        type=Path,
        default=None,
        help="Optional path to compiled GCLIENT.exe to stage transitive DLL closure into artifact_dir first.",
    )
    parser.add_argument(
        "--search-dir",
        action="append",
        type=Path,
        default=[],
        help="Ordered DLL/PDB search directories for --stage-from-root-exe (may be passed multiple times).",
    )
    parser.add_argument(
        "--pdb-output-dir",
        type=Path,
        default=None,
        help="Optional directory to stage matching .pdb symbol files during --stage-from-root-exe.",
    )
    parser.add_argument(
        "--expected-lua51-sha256",
        default="",
        help="Expected SHA-256 of freshly built LuaJIT 2.0.1 v143 lua51.dll.",
    )
    parser.add_argument(
        "--luajit-provenance",
        type=Path,
        default=None,
        help="Path to luajit-provenance.json produced by tools/build_luajit_vs2022.ps1.",
    )
    parser.add_argument(
        "--require-app-local-vc-redist",
        action="store_true",
        help="Fail if vcruntime140.dll / msvcp140.dll are not bundled inside artifact_dir.",
    )
    parser.add_argument(
        "--dumpbin",
        default="",
        help="Optional path to MSVC dumpbin.exe for native cross-checking on Windows.",
    )
    parser.add_argument(
        "--manifest-out",
        type=Path,
        default=None,
        help="Output path for machine-readable dependency-manifest.json.",
    )
    parser.add_argument(
        "--sha256-out",
        type=Path,
        default=None,
        help="Output path for SHA256SUMS.txt.",
    )
    parser.add_argument(
        "--fail-on-unreferenced",
        action="store_true",
        help="Fail if any unreferenced .dll/.exe exists in artifact_dir.",
    )
    args = parser.parse_args(argv)

    if args.stage_from_root_exe is not None:
        if not args.stage_from_root_exe.is_file():
            print(f"[ERROR] --stage-from-root-exe not found: {args.stage_from_root_exe}", file=sys.stderr)
            return 2
        staged = stage_transitive_closure(
            root_exe=args.stage_from_root_exe,
            dest_dir=args.artifact_dir,
            search_dirs=args.search_dir,
            pdb_dest_dir=args.pdb_output_dir,
        )
        print(f"[PE-Stage] Staged {len(staged)} transitive binaries into {args.artifact_dir}: {', '.join(staged)}")

    if not args.artifact_dir.is_dir():
        print(f"[ERROR] Artifact directory not found: {args.artifact_dir}", file=sys.stderr)
        return 2

    expected_lua_sha = args.expected_lua51_sha256
    if not expected_lua_sha and args.luajit_provenance and args.luajit_provenance.is_file():
        prov = json.loads(args.luajit_provenance.read_text(encoding="utf-8"))
        expected_lua_sha = str(prov.get("lua51_dll_sha256", ""))

    manifest = audit_artifact_directory(
        artifact_dir=args.artifact_dir,
        root_exe_name=args.root_exe,
        expected_lua51_sha256=expected_lua_sha,
        allow_system_vc_redist=(not args.require_app_local_vc_redist),
        dumpbin_exe=args.dumpbin,
    )

    if args.fail_on_unreferenced and manifest.unreferenced_staged_binaries:
        manifest.violations.append(
            "Unreferenced dead binaries present in artifact: "
            + ", ".join(manifest.unreferenced_staged_binaries)
        )
        manifest.passed = False

    manifest_out = args.manifest_out or (args.artifact_dir / "dependency-manifest.json")
    manifest_out.parent.mkdir(parents=True, exist_ok=True)
    manifest_out.write_text(json.dumps(asdict(manifest), indent=2), encoding="utf-8", newline="\n")

    sha_out = args.sha256_out or (args.artifact_dir / "SHA256SUMS.txt")
    write_sha256_sums(args.artifact_dir, sha_out)

    print("=" * 78)
    print(f"PE32 Transitive Dependency & CRT Audit: {'PASSED' if manifest.passed else 'FAILED'}")
    print("=" * 78)
    print(f"Artifact Dir       : {manifest.artifact_dir}")
    print(f"Shipped Closure    : {len(manifest.transitive_closure_shipped)} binaries ({', '.join(manifest.transitive_closure_shipped)})")
    print(f"VC143 Redist CRTs  : {', '.join(manifest.vc_redist_crt_dependencies) or '(none)'}")
    print(f"Windows OS / UCRT  : {', '.join(manifest.transitive_os_dependencies)}")
    if manifest.unreferenced_staged_binaries:
        print(f"Unreferenced DLLs  : {', '.join(manifest.unreferenced_staged_binaries)}")
    if manifest.violations:
        print("-" * 78)
        for v in manifest.violations:
            print(f"  [VIOLATION] {v}")
        print("=" * 78)
        return 1

    print("=" * 78)
    return 0


if __name__ == "__main__":
    sys.exit(main())
