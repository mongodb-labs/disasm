import sys, os
from capstone import *
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from demangler import demangle

# list of function symbols
def get_function_syms(elff):
    symtab = elff.get_section_by_name(".symtab")
    function_syms = list(filter(lambda sym: sym["st_info"]["type"] == "STT_FUNC", symtab.iter_symbols()))
    return function_syms

# given file, return list of function locations
# {
#    "offset": <bytes from beginning of file f>,
#    "size": <size of function>,
#    "sym": <Symbol object from symbol table>
# }
def get_functions(path):
    with open(path, 'rb') as f:
        elff = ELFFile(f)
        functions = _get_functions(elff)
    return functions

def _get_functions(elff):
    print "getting functions"
    function_syms = get_function_syms(elff)

    # get offset and beginning of .text section
    # *** currently assuming all functions always in .text TODO!!!!!!!!!!!
    # there are some symbols that cause the offset to go negative so yeah let's fix that
    section = elff.get_section_by_name(".text")

    functions = []
    #  load info for each symbol into functions[]
    for sym in function_syms:
        func = {}
        func["offset"] = sym["st_value"] - section["sh_addr"] + section["sh_offset"]
        func["size"] = sym["st_size"]
        sym.name = demangle(sym.name)
        func["sym"] = sym
        functions.append(func)

    return functions

# use capstone to disassemble from path, given optional offset and optional size
# return array of instructions
def disasm(filepath, offset=0, size=-1):
    with open(filepath, 'rb') as f:
        disassembled = _disasm(f, offset, size)
    return disassembled

def _disasm(f, offset=0, size=-1):
    print "offset %i, size %i" % (offset, size)

    # option to limit size
    f.seek(int(offset))
    if size == -1:
        CODE = f.read()
    else:
        CODE = f.read(int(size))

    # disassemble
    try:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        # disassembled = md.disasm(CODE, offset)
        disassembled = list(md.disasm(CODE, offset))
        for i in disassembled:
            print "0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str)
        return disassembled

    except CsError as e:
        print("ERROR: %s" %e)

########### mostly for testing ###########
# disassemble all functions
def disassemble_all(path):
    with open(path, 'rb') as f:
        elff = ELFFile(f)
        functions = _get_functions(elff)
        for func in functions:
            print "Disassembling function", func["sym"].name
            return _disasm(f, func["offset"], func["size"])

# disassemble function at index
def disassemble_at_index(path, i):
    with open(path, 'rb') as f:
        elff = ELFFile(f)
        func = _get_functions(elff)[int(i)]
        return _disasm(f, func["offset"], func["size"])


if __name__ == "__main__":
    if len(sys.argv) == 2:
        disassemble_all(sys.argv[1])
    elif len(sys.argv) == 3:
        disassemble_at_index(sys.argv[1], sys.argv[2])
    else:
        print "disasm <executable> | disasm <executable> <function index>"
