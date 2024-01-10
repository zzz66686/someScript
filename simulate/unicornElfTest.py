from unicorn import *
from unicorn.arm64_const import *
from capstone import *


from elftools.elf.elffile import ELFFile



md=Cs(CS_ARCH_ARM64,CS_MODE_ARM |CS_MODE_LITTLE_ENDIAN)
emu = Uc(UC_ARCH_ARM64, UC_MODE_ARM | UC_MODE_LITTLE_ENDIAN)  

def hook_code(uc, address, size, user_data):
    bytecode=emu.mem_read(address,size)
    for i in md.disasm(bytecode,address):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
    if address == 0x0591498:
        w0 = emu.reg_read(UC_ARM64_REG_W0)
        w1 =  emu.reg_read(UC_ARM64_REG_W1)
        print("w0:0x%08X, 0x%08X" % (w0, w1))
        

if __name__ == "__main__":
    with open("tb_diagserver", 'rb') as elffile:
        elf=ELFFile(elffile)
        load_segments = [x for x in elf.iter_segments() if x.header.p_type == 'PT_LOAD']
 
        for segment in load_segments:
            print('mem_map: addr=0x%x  size=0x%x'%(segment.header.p_vaddr,segment.header.p_memsz))
            
            mapaddr =   (int(segment.header.p_vaddr / 0x1000) - 1) *  0x1000
            mapsize =  (int(segment.header.p_memsz / 0x1000) + 2) *  0x1000
            
            emu.mem_map(mapaddr, mapsize, UC_PROT_ALL)
            emu.mem_write(segment.header.p_vaddr, segment.data())    


    stack_base = 0x1000000
    stack_size =  2 * 1024 * 1024
    emu.mem_map(stack_base, stack_size)
    emu.reg_write(UC_ARM64_REG_SP ,stack_base+stack_size)
    
    #emu.hook_add(UC_HOOK_CODE, hook_code)
    
    emu.reg_write(UC_ARM64_REG_W0, 0xaa1111bb)
    emu.emu_start(0x591344, 0x5914E8)
    ret = emu.reg_read(UC_ARM64_REG_W0)
    
    print("0x%08X" % ret)



