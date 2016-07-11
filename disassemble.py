import sys, os
from capstone import Cs, CsError, CS_ARCH_X86, CS_MODE_64, x86
import pdb
import executable

# given a sequence of bytes and an optional offset within the file (for display
# purposes) return assembly for those bytes
def disasm(bytes, offset=0):
    print "offset %i" % offset
    try:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        disassembled = list(md.disasm(bytes, offset))
        for i, instr in enumerate(disassembled):
            # if instr.address == 11524206:
            #     pdb.set_trace()
            print "0x%x:\t%s\t%s" % (instr.address, instr.mnemonic, instr.op_str)
            for op in instr.operands:
                if op.type == x86.X86_OP_MEM and op.mem.base == x86.X86_REG_RIP:
                    instr.rip = True
                    instr.offset = op.mem.disp
                    instr.resolved = disassembled[i+1].address + instr.offset
                    instr.symbol = executable.ex.get_bytes(instr.resolved, op.size)
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
        # If this instruction contains a rip-relative address, then assign the relevant data
        if i.rip:
            row['rip'] = True
            row['rip-offset'] = i.offset
            row['rip-resolved'] = i.resolved
            row['rip-symbol'] = i.symbol
        ret.append(row)
    return ret