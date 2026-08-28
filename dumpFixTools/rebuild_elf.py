#!/usr/bin/env python3
"""
Rebuild a packed ELF shared library / executable by patching decrypted memory
dumps. File mirrors memory: p_offset == p_vaddr for every PT_LOAD segment, so
dump bytes can be patched at offset == RVA without colliding with anything --
exactly the trick rebuild_dll.py uses for PE.

Usage:
  pip install pyelftools
  python3 rebuild_elf.py <original.so> <dump_dir> <output.so>

meta.txt format:
  module=libapp.so
  base=0x71bbc00000
  size=0x27e1000
  seg0 off=0x0      size=0xaf0000 prot=r-x
  seg1 off=0xaf0000 size=0x1000   prot=r-x
  ...
"""

from elftools.elf.elffile import ELFFile
import struct
import sys
import os
import glob
import re

if len(sys.argv) != 4:
    print(f"Usage: {sys.argv[0]} <original.so> <dump_dir> <output.so>")
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
# Load original ELF and capture key parameters
# ============================================================
with open(original_path, 'rb') as f:
    orig = f.read()

elf = ELFFile(__import__('io').BytesIO(orig))
is_64       = elf.elfclass == 64
endian      = '<' if elf.little_endian else '>'
e_phoff     = elf.header.e_phoff
e_phnum     = elf.header.e_phnum
e_phentsize = elf.header.e_phentsize
e_shoff     = elf.header.e_shoff
e_shnum     = elf.header.e_shnum
e_shentsize = elf.header.e_shentsize
e_shstrndx  = elf.header.e_shstrndx

ADDR_FMT = f'{endian}Q' if is_64 else f'{endian}I'
WORD     = 8 if is_64 else 4

# Phdr field offsets
if is_64:
    PH_TYPE, PH_FLAGS, PH_OFFSET, PH_VADDR, PH_PADDR, PH_FILESZ, PH_MEMSZ, PH_ALIGN = \
        0, 4, 8, 16, 24, 32, 40, 48
else:
    PH_TYPE, PH_OFFSET, PH_VADDR, PH_PADDR, PH_FILESZ, PH_MEMSZ, PH_FLAGS, PH_ALIGN = \
        0, 4, 8, 12, 16, 20, 24, 28

# Shdr field offsets (same layout for ELF32/ELF64, just different widths)
if is_64:
    SH_NAME, SH_TYPE, SH_FLAGS, SH_ADDR, SH_OFFSET, SH_SIZE, SH_LINK, SH_INFO, SH_ALIGN, SH_ENTSIZE = \
        0, 4, 8, 16, 24, 32, 40, 44, 48, 56
else:
    SH_NAME, SH_TYPE, SH_FLAGS, SH_ADDR, SH_OFFSET, SH_SIZE, SH_LINK, SH_INFO, SH_ALIGN, SH_ENTSIZE = \
        0, 4, 8, 12, 16, 20, 24, 28, 32, 36

PT_LOAD    = 1
PT_DYNAMIC = 2

# Read original phdrs
phdrs = []
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    ph = {
        'idx':    i,
        'off_in_file': off,
        'p_type':   struct.unpack_from(f'{endian}I', orig, off + PH_TYPE)[0],
        'p_flags':  struct.unpack_from(f'{endian}I', orig, off + PH_FLAGS)[0],
        'p_offset': struct.unpack_from(ADDR_FMT, orig, off + PH_OFFSET)[0],
        'p_vaddr':  struct.unpack_from(ADDR_FMT, orig, off + PH_VADDR)[0],
        'p_paddr':  struct.unpack_from(ADDR_FMT, orig, off + PH_PADDR)[0],
        'p_filesz': struct.unpack_from(ADDR_FMT, orig, off + PH_FILESZ)[0],
        'p_memsz':  struct.unpack_from(ADDR_FMT, orig, off + PH_MEMSZ)[0],
        'p_align':  struct.unpack_from(ADDR_FMT, orig, off + PH_ALIGN)[0],
    }
    phdrs.append(ph)

# Original module base (vaddr of the lowest PT_LOAD, minus its file offset).
# For shared libs this is typically 0; for ET_EXEC binaries it can be non-zero.
load_phdrs = [p for p in phdrs if p['p_type'] == PT_LOAD]
if not load_phdrs:
    print("[!] No PT_LOAD segments?!")
    sys.exit(1)

original_base = min(p['p_vaddr'] - p['p_offset'] for p in load_phdrs)
image_size    = max(p['p_vaddr'] + p['p_memsz'] for p in load_phdrs) - original_base

print(f"[*] ELF class:       {'64-bit' if is_64 else '32-bit'} {elf.header.e_machine}")
print(f"[*] Original base:   0x{original_base:x}")
print(f"[*] Image size:      0x{image_size:x}")

print("\nOriginal PT_LOAD segments:")
for p in load_phdrs:
    flag_str = ("r" if p['p_flags'] & 4 else "-") + \
               ("w" if p['p_flags'] & 2 else "-") + \
               ("x" if p['p_flags'] & 1 else "-")
    bss = " [BSS]" if p['p_filesz'] < p['p_memsz'] else ""
    print(f"  off=0x{p['p_offset']:08x} vaddr=0x{p['p_vaddr']:012x} "
          f"filesz=0x{p['p_filesz']:08x} memsz=0x{p['p_memsz']:08x} {flag_str}{bss}")

# ============================================================
# Build a flat memory image: data[i] == byte at RVA i
# Step 1: copy each PT_LOAD's bytes from original file at offset == p_vaddr - base
# Step 2: patch dumps over the top
# Step 3: rewrite phdrs so file == memory layout
# Step 4: rewrite section table similarly
# ============================================================
print("\n[*] Building flat memory image...")

data = bytearray(image_size)

# Step 1: Original PT_LOAD bytes at VA-based offsets. Anything not covered
# by a dump (notably read-only data, GOT entries, etc.) is preserved.
for p in load_phdrs:
    rva = p['p_vaddr'] - original_base
    n   = min(p['p_filesz'], image_size - rva)
    if n > 0:
        data[rva:rva + n] = orig[p['p_offset']:p['p_offset'] + n]

# ============================================================
# Step 2: Patch dump files. Each dump is named <prefix>0xRVA.bin where RVA is
# the offset from the runtime module base. File == memory now, so we just
# write the dump at offset == RVA.
# ============================================================
# Accept both the dump_elf.js convention `<prefix>_0x<rva>.bin` and the
# shell-script convention `<prefix>_<rva-no-prefix>.bin`.
dump_files = sorted(glob.glob(os.path.join(dump_dir, "*.bin")))
print(f"\nPatching {len(dump_files)} dump files at file_offset == RVA:")
for dump_file in dump_files:
    base = os.path.basename(dump_file)
    match = re.search(r'_(0x)?([0-9a-fA-F]+)\.bin$', base)
    if not match:
        print(f"  [skip] {base} (no recognizable hex offset)")
        continue
    rva = int(match.group(2), 16)
    # Two filename conventions in the wild:
    #   dump_elf.js:    `<prefix>_0x<RVA>.bin`     (offset from module base)
    #   shell+maps.txt: `<prefix>_<absolute_VA>.bin`
    # If the parsed value falls inside the image's VA range, it's an absolute
    # VA and we need to subtract the load base; otherwise treat it as an RVA.
    if original_base <= rva < original_base + image_size:
        rva -= original_base
    with open(dump_file, 'rb') as f:
        dump_data = f.read()
    end = rva + len(dump_data)
    if end > len(data):
        # Dump extends past the original image; grow buffer
        data.extend(b'\x00' * (end - len(data)))
    data[rva:end] = dump_data
    print(f"  0x{rva:08x} ({len(dump_data):>10} bytes) -> file 0x{rva:08x}")

final_image_size = len(data)
if final_image_size > image_size:
    print(f"[!] Dumps extend past original image; growing 0x{image_size:x} -> 0x{final_image_size:x}")
    image_size = final_image_size

# ============================================================
# Step 3: Rewrite program headers in `data` so file == memory:
#   - p_offset = p_vaddr - base
#   - p_filesz = p_memsz   (BSS now lives in the file)
#   - if rebasing, add rebase_offset to p_vaddr / p_paddr
# Phdrs live at e_phoff in the file. In a normal ELF, e_phoff is inside
# PT_LOAD[0] (at offset 0x40 or so), so the bytes we just copied include
# the phdr table -- we patch in place.
# ============================================================
# Option A: keep the file self-describing at its original base (typically 0)
# and let IDA's loader dialog place the image at `runtime_base`. IDA shifts
# every VA-bearing field uniformly at load time, so we don't have to rewrite
# st_value / .dynamic / r_offset here. runtime_base is kept only as a hint
# printed at the end -- it does NOT get baked into the file.
rebase_offset = 0
if runtime_base is not None and runtime_base != original_base:
    print(f"\n[*] Runtime base 0x{runtime_base:x} will NOT be baked into the file.")
    print(f"    Set 'Image base' = 0x{runtime_base:x} in IDA's loader dialog.")

print("\nRewriting program headers (file == memory):")
for p in phdrs:
    off = p['off_in_file']
    new_offset = p['p_offset']
    new_filesz = p['p_filesz']
    new_vaddr  = p['p_vaddr']  + rebase_offset
    new_paddr  = p['p_paddr']  + rebase_offset

    if p['p_type'] == PT_LOAD:
        # Make the file image match memory: file offset == RVA.
        new_offset = p['p_vaddr'] - original_base
        new_filesz = p['p_memsz']
    elif p['p_filesz'] > 0:
        # Any phdr that references file data (PT_DYNAMIC, PT_INTERP,
        # PT_NOTE, PT_PHDR, PT_TLS, PT_GNU_EH_FRAME, PT_GNU_RELRO, ...)
        # lives inside a PT_LOAD; its file offset now == p_vaddr - base.
        # filesz stays as-is -- only PT_LOAD owns BSS extension.
        new_offset = p['p_vaddr'] - original_base

    struct.pack_into(ADDR_FMT,        data, off + PH_OFFSET, new_offset)
    struct.pack_into(ADDR_FMT,        data, off + PH_VADDR,  new_vaddr)
    struct.pack_into(ADDR_FMT,        data, off + PH_PADDR,  new_paddr)
    struct.pack_into(ADDR_FMT,        data, off + PH_FILESZ, new_filesz)
    if p['p_type'] == PT_LOAD:
        flag_str = ("r" if p['p_flags'] & 4 else "-") + \
                   ("w" if p['p_flags'] & 2 else "-") + \
                   ("x" if p['p_flags'] & 1 else "-")
        bss_grew = " [BSS->file]" if p['p_filesz'] < p['p_memsz'] else ""
        print(f"  PT_LOAD  vaddr=0x{new_vaddr:012x} off=0x{new_offset:08x} "
              f"filesz=0x{new_filesz:08x} memsz=0x{p['p_memsz']:08x} {flag_str}{bss_grew}")

# Update e_entry if rebasing
if rebase_offset:
    e_entry_off = 24 if is_64 else 24
    e_entry = struct.unpack_from(ADDR_FMT, data, e_entry_off)[0]
    if e_entry:
        struct.pack_into(ADDR_FMT, data, e_entry_off, e_entry + rebase_offset)
        print(f"[*] Rebased e_entry: 0x{e_entry:x} -> 0x{e_entry + rebase_offset:x}")

# ============================================================
# Step 4: Section header table.
# In the original file e_shoff usually points past the last PT_LOAD's file
# data; our new image is bigger, so the section table needs to move. We
# also rewrite each section's sh_offset/sh_addr so they're consistent with
# the new file == memory layout.
#
#   - For loadable sections (sh_addr != 0): sh_offset = sh_addr - base
#                                            sh_addr  = sh_addr + rebase
#   - For non-loadable sections (sh_addr == 0): preserve original data by
#     appending it to the new file and updating sh_offset.
#   - Section header table is appended after everything else.
# ============================================================
sections_appended = []  # list of (idx, new_offset, size) for non-loadable
if e_shnum > 0 and e_shoff > 0:
    sh_data = bytearray(orig[e_shoff:e_shoff + e_shnum * e_shentsize])

    # First pass: append non-loadable section bytes to the end of `data`.
    # Section data is placed at file_offset = current end-of-file, padded
    # to 8 bytes for alignment safety.
    for i in range(e_shnum):
        soff = i * e_shentsize
        sh_type   = struct.unpack_from(f'{endian}I', sh_data, soff + SH_TYPE)[0]
        sh_addr   = struct.unpack_from(ADDR_FMT,     sh_data, soff + SH_ADDR)[0]
        sh_off    = struct.unpack_from(ADDR_FMT,     sh_data, soff + SH_OFFSET)[0]
        sh_size   = struct.unpack_from(ADDR_FMT,     sh_data, soff + SH_SIZE)[0]

        if sh_type == 0:  # SHT_NULL
            continue

        if sh_addr != 0:
            # Loadable section -- it lives in the memory image at sh_addr.
            new_off  = sh_addr - original_base
            new_addr = sh_addr + rebase_offset
            struct.pack_into(ADDR_FMT, sh_data, soff + SH_OFFSET, new_off)
            struct.pack_into(ADDR_FMT, sh_data, soff + SH_ADDR,   new_addr)
        else:
            # Non-loadable (.symtab, .strtab, .shstrtab, .debug_*). Append
            # original bytes to the end of the file and update sh_offset.
            if sh_size == 0:
                continue
            # Pad to 8-byte alignment
            if len(data) & 7:
                data.extend(b'\x00' * (8 - (len(data) & 7)))
            new_off = len(data)
            data.extend(orig[sh_off:sh_off + sh_size])
            struct.pack_into(ADDR_FMT, sh_data, soff + SH_OFFSET, new_off)
            # IDA's "Manual load" mode adds the user-chosen image base to
            # every section's sh_addr -- even non-SHF_ALLOC ones, which a
            # strict ELF loader wouldn't map at all. Leaving sh_addr=0
            # causes .shstrtab/.symtab/.strtab to be placed at image_base
            # and overlay PT_LOAD[0]. Park them at their (post-image) file
            # offset instead: still outside any PT_LOAD range after offset,
            # so no collision. SHF_ALLOC stays 0, so any non-IDA loader
            # still ignores these.
            struct.pack_into(ADDR_FMT, sh_data, soff + SH_ADDR, new_off)
            sections_appended.append((i, new_off, sh_size))

    # Second pass: append the section header table itself.
    if len(data) & 7:
        data.extend(b'\x00' * (8 - (len(data) & 7)))
    new_shoff = len(data)
    data.extend(sh_data)

    # Write new e_shoff into ELF header (offset 40 for ELF64, 32 for ELF32)
    e_shoff_field = 40 if is_64 else 32
    struct.pack_into(ADDR_FMT, data, e_shoff_field, new_shoff)
    print(f"\n[*] Section header table relocated: 0x{e_shoff:x} -> 0x{new_shoff:x}")
    if sections_appended:
        print(f"[*] Appended {len(sections_appended)} non-loadable sections after image")
else:
    print("\n[*] No section header table to fix up")

# ============================================================
# Save
# ============================================================
with open(output_path, 'wb') as f:
    f.write(data)

final_base = runtime_base if runtime_base is not None else original_base
print(f"\nOutput: {output_path} ({len(data)} bytes)")
print(f"Load in IDA at base: 0x{final_base:x}")
