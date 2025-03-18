import ida_kernwin
import idaapi
import ida_name
import idautils
import idc


file_path = ida_kernwin.ask_file(0, "*.*", "Select a file to import")
if file_path:
    func_dict = {}
    fp = open(file_path, "r")
    for line in fp.readlines():
        content = line.strip()
        if content:
            # Split "ffffffff81000000 T _text"
            items = content.split(' ')
            address = int(items[0], 16)
            name = items[2]
            func_dict[address] = name
    fp.close()
    for func_address in idautils.Functions():
        if func_address in func_dict:
            ida_name.set_name(func_address, func_dict[func_address], ida_name.SN_NOWARN)
    print(f"Import kallsyms successfully.")
