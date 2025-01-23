from unicorn import *
from unicorn.arm64_const import *
from capstone import *


from elftools.elf.elffile import ELFFile

import hexdump


md=Cs(CS_ARCH_ARM64,CS_MODE_ARM |CS_MODE_LITTLE_ENDIAN)
emu = Uc(UC_ARCH_ARM64, UC_MODE_ARM | UC_MODE_LITTLE_ENDIAN)  

def hook_code(uc, address, size, user_data):
    bytecode=emu.mem_read(address,size)
    for i in md.disasm(bytecode,address):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        
    if address == 0x2240: #memcpy
        dst = emu.reg_read(UC_ARM64_REG_X0)
        src =  emu.reg_read(UC_ARM64_REG_X1)
        n = emu.reg_read(UC_ARM64_REG_X2)
        
        data = emu.mem_read(src, n)
        emu.mem_write(dst, bytes(data))
        
        lr = emu.reg_read(UC_ARM64_REG_LR)
        emu.reg_write(UC_ARM64_REG_PC, lr)
        
        
    if address == 0x2170: #hsmcli_reqPrm_init
        emu.reg_write(UC_ARM64_REG_PC, 0x5BB0)
        
    if address == 0x2260: #hsmcli_prm_getp_msg_hdr
        emu.reg_write(UC_ARM64_REG_PC, 0x5B50)
        
    if address == 0x22B0: #hsmcli_prm_getp_msg
        emu.reg_write(UC_ARM64_REG_PC, 0x5B48)
        
    if address == 0x2320: #hsmcli_reqPrm_getp_payload
        emu.reg_write(UC_ARM64_REG_PC, 0x5B68)
        
    if address == 0x22B0: #hsmcli_prm_getp_msg
        emu.reg_write(UC_ARM64_REG_PC, 0x5B48)
        
    if address == 0x2470: #hsmcli_respPrm_init
        emu.reg_write(UC_ARM64_REG_PC, 0x5C48)
        
        

if __name__ == "__main__":
    with open("libdjihsm.so", 'rb') as elffile:
        elf=ELFFile(elffile)
        load_segments = [x for x in elf.iter_segments() if x.header.p_type == 'PT_LOAD']
 
        for segment in load_segments:
            print('mem_map: addr=0x%x  size=0x%x'%(segment.header.p_vaddr,segment.header.p_memsz))
            
            mapaddr =   (int(segment.header.p_vaddr / 0x1000)) *  0x1000
            mapsize =  (int(segment.header.p_memsz / 0x1000) + 2) *  0x1000
            
            emu.mem_map(mapaddr, mapsize, UC_PROT_ALL)
            emu.mem_write(segment.header.p_vaddr, segment.data())    


    stack_base = 0x1000000
    stack_size =  2 * 1024 * 1024
    emu.mem_map(stack_base, stack_size)
    emu.reg_write(UC_ARM64_REG_SP ,stack_base+stack_size)
    
    heap_base = 0x2000000
    heap_size =  2 * 1024 * 1024
    emu.mem_map(heap_base, heap_size)
    
    
    
    emu.hook_add(UC_HOOK_CODE, hook_code)
    
    
    originData = b'\xa2\xbb\x11\x90\x26\xa6\x82\x89\xeb\x2b\xad\x32\x94\x5b\xbc\xca'
    emu.mem_write(heap_base, originData)
    originData2 = b'\x44\x4a\x49\x2d\x53\x4d\x45\x4b'
    emu.mem_write(heap_base + 0x1000, originData2)
    
    
    emu.reg_write(UC_ARM64_REG_X0, heap_base + 0x1000)
    emu.reg_write(UC_ARM64_REG_X1, 0x10)
    emu.reg_write(UC_ARM64_REG_X2, heap_base)
    emu.reg_write(UC_ARM64_REG_X3, 0)
    emu.reg_write(UC_ARM64_REG_X4, 0x20)
    emu.reg_write(UC_ARM64_REG_X5, 0xa)
    emu.reg_write(UC_ARM64_REG_X6, heap_base+0x2000)
    
    
    emu.emu_start(0x02B00, 0x2BD4)
    retX0 = emu.reg_read(UC_ARM64_REG_X0)
    print("0x%08X" % retX0)
    x0Data = emu.mem_read(retX0, 64)
    hexdump.hexdump(x0Data)
    
    
    retX1 = emu.reg_read(UC_ARM64_REG_X1)
    print("0x%08X" % retX1)
    x1Data = emu.mem_read(retX1, 64)
    hexdump.hexdump(x1Data)    
    
    
