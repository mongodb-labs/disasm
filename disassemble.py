import sys, os
from capstone import *

# given a sequence of bytes and an optional offset within the file (for display
# purposes) return assembly for those bytes
def disasm(bytes, offset=0):
    print "offset %i" % offset
    try:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        disassembled = list(md.disasm(bytes, offset))
        for i in disassembled:
            print "0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str)
        return disassembled

    except CsError as e:
        print("ERROR: %s" %e)

# class CsInsn exposes all the internal information about the disassembled 
# instruction that we want to access to
def jsonify_capstone(data):
    ret = []
    for i in data:
        row = {
            "id": i.id,
            "address": i.address,
            "mnemonic": i.mnemonic,
            "op_str": i.op_str,
            "size": i.size,
            # "bytes": i.bytes # json can't serialize byte array
        }
        ret.append(row)
    return ret