#!/usr/bin/env python3
"""
Rebuild a packed PE DLL by patching decrypted memory dumps.
File mirrors memory: PointerToRawData == VirtualAddress for every section,
FileAlignment == SectionAlignment, so dump bytes can be patched at offset == RVA
without colliding with anything.

Usage:
  pip install pefile
  python3 rebuild_dll.py <original.dll> <dump_dir> <output.dll>

meta.txt format:
  module=bambu_networking.dll
  base=0x7ff812340000
  size=0xf6a000
  seg0 off=0x0 size=0x5e3000 prot=r-x
  seg1 off=0x5e4000 size=0x11f0 prot=r-x
  ...
"""

import pefile
import struct
import sys
import os
import glob
import re

if len(sys.argv) != 4:
    print(f"Usage: {sys.argv[0]} <original.dll> <dump_dir> <output.dll>")
    sys.exit(1)

original_path, dump_dir, output_path = sys.argv[1], sys.argv[2], sys.argv[3]


def align_up(x, a):
    return (x + a - 1) & ~(a - 1)


# ============================================================
# Parse meta.txt for runtime base address
# ============================================================
runtime_base = None
meta_files = glob.glob(os.path.join(dump_dir, "*meta*"))
for mf in meta_files:
    with open(mf) as f:
        for line in f:
            line = line.strip()
            if line.startswith("base="):
                val = line.split("=", 1)[1].strip()
                # Handle "0x0x..." typo (seen in some Frida output)
                val = val.replace("0x0x", "0x")
                runtime_base = int(val, 0)
                print(f"[*] Runtime base from {os.path.basename(mf)}: 0x{runtime_base:x}")

# ============================================================
# Load original PE and capture key parameters
# ============================================================
pe = pefile.PE(original_path)
original_base   = pe.OPTIONAL_HEADER.ImageBase
size_of_image   = pe.OPTIONAL_HEADER.SizeOfImage
size_of_headers = pe.OPTIONAL_HEADER.SizeOfHeaders
sec_alignment   = pe.OPTIONAL_HEADER.SectionAlignment

print(f"[*] Original ImageBase:   0x{original_base:x}")
print(f"[*] SizeOfImage:          0x{size_of_image:x}")
print(f"[*] SizeOfHeaders:        0x{size_of_headers:x}")
print(f"[*] SectionAlignment:     0x{sec_alignment:x}")
print(f"[*] FileAlignment:        0x{pe.OPTIONAL_HEADER.FileAlignment:x} -> 0x{sec_alignment:x}")

# ============================================================
# Show original section layout
# ============================================================
print(f"\nOriginal sections ({len(pe.sections)}):")
for sec in pe.sections:
    name = sec.Name.rstrip(b'\x00').decode('ascii', errors='replace')
    bss = " [BSS]" if sec.SizeOfRawData == 0 and sec.Misc_VirtualSize > 0 else ""
    print(f"  {name:10s} VA=0x{sec.VirtualAddress:08x} VS=0x{sec.Misc_VirtualSize:08x} "
          f"RawPtr=0x{sec.PointerToRawData:08x} RawSize=0x{sec.SizeOfRawData:08x}{bss}")

# ============================================================
# Build a flat memory image: bytes[i] == byte at RVA i
# Step 1: copy headers from the original file
# Step 2: copy each original section's raw data into VA-based offset
# Step 3: patch dumps over the top
# Step 4: rewrite section table so file == memory layout
# ============================================================
print("\n[*] Building flat memory image...")

with open(original_path, 'rb') as f:
    orig = f.read()

data = bytearray(size_of_image)

# Headers
data[:size_of_headers] = orig[:size_of_headers]

# Original section raw data, placed at VA-based offsets so we don't lose
# any initialised bytes that aren't covered by a dump.
for sec in pe.sections:
    rs = sec.SizeOfRawData
    if rs == 0:
        continue
    rp = sec.PointerToRawData
    va = sec.VirtualAddress
    n  = min(rs, size_of_image - va)
    if n > 0:
        data[va:va + n] = orig[rp:rp + n]

# ============================================================
# Patch dump files. Each dump is named <prefix>_<rva>.bin or <prefix>_0x<rva>.bin
# where rva is the offset from the runtime module base (== virtual offset).
# Some dumpers write the absolute VA instead; if the parsed value falls inside
# [ImageBase, ImageBase + SizeOfImage), treat it as a VA and subtract ImageBase.
# Memory == file, so we just write the dump at offset == RVA.
# ============================================================
dump_files = sorted(glob.glob(os.path.join(dump_dir, "*.bin")))
print(f"\nPatching dump files at file_offset == RVA:")
for dump_file in dump_files:
    base = os.path.basename(dump_file)
    match = re.search(r'_(?:0x)?([0-9a-fA-F]+)\.bin$', base)
    if not match:
        print(f"  [skip] {base} (no recognizable hex offset)")
        continue
    rva = int(match.group(1), 16)
    # Absolute-VA filename convention: convert to RVA.
    if original_base <= rva < original_base + size_of_image:
        rva -= original_base
    with open(dump_file, 'rb') as f:
        dump_data = f.read()
    end = rva + len(dump_data)
    if end > len(data):
        # Dump extends past SizeOfImage; grow buffer
        data.extend(b'\x00' * (end - len(data)))
    data[rva:end] = dump_data
    print(f"  0x{rva:08x} ({len(dump_data):>10} bytes) -> file 0x{rva:08x}")

final_size = len(data)
if final_size > size_of_image:
    print(f"[!] Dumps extend past SizeOfImage; growing 0x{size_of_image:x} -> 0x{final_size:x}")
    size_of_image = align_up(final_size, sec_alignment)
    if size_of_image > final_size:
        data.extend(b'\x00' * (size_of_image - final_size))

# ============================================================
# Rewrite headers in `data` to reflect the new layout:
#   - ImageBase = runtime_base
#   - FileAlignment = SectionAlignment
#   - Each section: PointerToRawData = VirtualAddress
#                   SizeOfRawData    = align_up(VirtualSize, SectionAlignment)
#   - SizeOfImage updated if grown
#   - Zero CheckSum and Security data directory
# ============================================================
e_lfanew = struct.unpack_from('<I', data, 0x3c)[0]
file_hdr_off = e_lfanew + 4
opt_hdr_off  = file_hdr_off + 20
size_of_opt  = struct.unpack_from('<H', data, file_hdr_off + 16)[0]
nsec         = struct.unpack_from('<H', data, file_hdr_off + 2)[0]
sec_tbl_off  = opt_hdr_off + size_of_opt

magic = struct.unpack_from('<H', data, opt_hdr_off)[0]
is_pe32_plus = (magic == 0x20b)

# OptionalHeader field offsets (PE32+ shown, PE32 differs only in ImageBase width)
# offset 24: ImageBase (8 bytes for PE32+, 4 bytes for PE32)
# offset 32 / 28: SectionAlignment
# offset 36 / 32: FileAlignment
# offset 56 / 56: SizeOfImage
# offset 60 / 60: SizeOfHeaders
# offset 64 / 64: CheckSum
# Data directories start at: PE32+ -> 112, PE32 -> 96
if is_pe32_plus:
    OFF_IMAGEBASE          = 24
    OFF_FILEALIGNMENT      = 36
    OFF_SIZEOFIMAGE        = 56
    OFF_CHECKSUM           = 64
    OFF_DLLCHARACTERISTICS = 70
    OFF_DATADIRS           = 112
    IMAGEBASE_FMT          = '<Q'
else:
    OFF_IMAGEBASE          = 28
    OFF_FILEALIGNMENT      = 32
    OFF_SIZEOFIMAGE        = 56
    OFF_CHECKSUM           = 64
    OFF_DLLCHARACTERISTICS = 70
    OFF_DATADIRS           = 96
    IMAGEBASE_FMT          = '<I'

# DataDirectory indices we touch
DD_SECURITY    = 4   # cert table, file-offset based -> stale after rebuild
DD_BASE_RELOC  = 5   # base relocations -> dumped bytes already hold final VAs

# DllCharacteristics bits we strip so nothing ever decides to rebase us
DLLC_HIGH_ENTROPY_VA = 0x0020
DLLC_DYNAMIC_BASE    = 0x0040

# ImageBase
if runtime_base is not None:
    struct.pack_into(IMAGEBASE_FMT, data, opt_hdr_off + OFF_IMAGEBASE, runtime_base)
    print(f"\n[*] Set ImageBase = 0x{runtime_base:x}")

# FileAlignment = SectionAlignment
struct.pack_into('<I', data, opt_hdr_off + OFF_FILEALIGNMENT, sec_alignment)
print(f"[*] Set FileAlignment = 0x{sec_alignment:x}")

# SizeOfImage
struct.pack_into('<I', data, opt_hdr_off + OFF_SIZEOFIMAGE, size_of_image)
print(f"[*] Set SizeOfImage = 0x{size_of_image:x}")

# CheckSum -> 0 (loader ignores for normal DLLs; signing is broken anyway)
struct.pack_into('<I', data, opt_hdr_off + OFF_CHECKSUM, 0)

# Security directory (cert table) is file-offset based; the bytes have moved,
# so the existing entry is meaningless. Zero it.
struct.pack_into('<II', data, opt_hdr_off + OFF_DATADIRS + DD_SECURITY * 8, 0, 0)

# Base Relocation directory: the dump already holds runtime-resolved absolute
# pointers. If anything (Windows loader picking a non-preferred base, IDA's
# rebase command, ASLR) walks .reloc and applies a delta, those pointers get
# double-shifted into garbage. Zero the directory so nobody ever walks it.
struct.pack_into('<II', data, opt_hdr_off + OFF_DATADIRS + DD_BASE_RELOC * 8, 0, 0)

# Strip DYNAMIC_BASE / HIGH_ENTROPY_VA so the loader and IDA both treat the
# chosen ImageBase as mandatory, not a hint.
dll_chars = struct.unpack_from('<H', data, opt_hdr_off + OFF_DLLCHARACTERISTICS)[0]
new_dll_chars = dll_chars & ~(DLLC_DYNAMIC_BASE | DLLC_HIGH_ENTROPY_VA)
struct.pack_into('<H', data, opt_hdr_off + OFF_DLLCHARACTERISTICS, new_dll_chars)

print("[*] Cleared CheckSum, Security & BaseReloc directories, ASLR flags")
print(f"    DllCharacteristics: 0x{dll_chars:04x} -> 0x{new_dll_chars:04x}")

# Section table: PointerToRawData = VirtualAddress, SizeOfRawData = aligned VS
print("\nNew section layout (file == memory):")
for i in range(nsec):
    so   = sec_tbl_off + i * 40
    name = bytes(data[so:so+8]).rstrip(b'\x00').decode('ascii', errors='replace')
    vs   = struct.unpack_from('<I', data, so + 8)[0]
    va   = struct.unpack_from('<I', data, so + 12)[0]
    new_rs = align_up(vs, sec_alignment)
    # Make sure SizeOfRawData covers any dump bytes that landed past VS too
    # (some sections in this dump set are larger than their declared VS).
    new_rs = max(new_rs, align_up(min(size_of_image, va + new_rs) - va, sec_alignment))
    struct.pack_into('<I', data, so + 16, new_rs)  # SizeOfRawData
    struct.pack_into('<I', data, so + 20, va)      # PointerToRawData
    print(f"  {name:10s} VA=0x{va:08x} VS=0x{vs:08x} -> RP=0x{va:08x} RS=0x{new_rs:08x}")

# ============================================================
# Save
# ============================================================
with open(output_path, 'wb') as f:
    f.write(data)

print(f"\nOutput: {output_path} ({len(data)} bytes)")
print(f"Load in IDA at base: 0x{runtime_base if runtime_base else original_base:x}")
