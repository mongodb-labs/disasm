import sys, os
from capstone import Cs, CsError, CS_ARCH_X86, CS_MODE_64, x86
import pdb
import executable
from demangler import demangle

# given a sequence of bytes and an optional offset within the file (for display
# purposes) return assembly for those bytes
def disasm(bytes, offset=0):
    print "offset %i" % offset
    try:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        disassembled = list(md.disasm(bytes, offset))
        for i, instr in enumerate(disassembled):
            # if instr.address == 11523750:
            #     pdb.set_trace()
            print "0x%x:\t%s\t%s" % (instr.address, instr.mnemonic, instr.op_str)
            # Check to see if it's a no-op instruction
            if instr.id == x86.X86_INS_NOP:
                instr.nop = True
            # Check to see if it's a jump/call instruction
            if instr.group(x86.X86_GRP_JUMP) or instr.group(x86.X86_GRP_CALL):
                # We can only decode the destination if it's an immediate value
                if instr.operands[0].type == x86.X86_OP_IMM:
                    # Ignore if it's a jump/call to an address within this function
                    func_start_addr = disassembled[0].address
                    func_end_addr = disassembled[len(disassembled)-1].address
                    dest_addr = instr.operands[0].imm
                    if not func_start_addr <= dest_addr <= func_end_addr:
                        symbol = executable.ex.get_symbol_by_addr(dest_addr)
                        if symbol:
                            # pdb.set_trace()
                            text_sect = executable.ex.elff.get_section_by_name(".text")
                            sect_addr = text_sect["sh_addr"]
                            sect_offset = text_sect["sh_offset"]
                            func_addr = symbol['st_value']

                            instr.jump = True
                            instr.jump_address = dest_addr
                            instr.jump_function_name = demangle(symbol.name)
                            instr.jump_function_address = func_addr
                            instr.jump_function_offset = func_addr - sect_addr + sect_offset
                            instr.jump_function_size = symbol['st_size']
                            instr.comment = demangle(symbol.name)
            for op in instr.operands:
                if op.type == x86.X86_OP_MEM and op.mem.base == x86.X86_REG_RIP:
                    instr.rip = True
                    instr.rip_offset = op.mem.disp
                    instr.rip_resolved = disassembled[i+1].address + instr.rip_offset
                    symbol = executable.ex.get_symbol_by_addr(instr.rip_resolved)
                    if symbol:
                        instr.comment = demangle(symbol.name)
                    bytes = executable.ex.get_bytes(instr.rip_resolved, op.size)
                    instr.rip_value_hex = ""
                    space = ""
                    for char in bytes:
                        instr.rip_value_hex += space + hex(ord(char))
                        space = " "
                    # HTML collapses consecutive spaces. For presentation purposes, replace spaces
                    # with &nbsp (non-breaking space)
                    nbsp_str = []
                    if op.size == 16:
                        for char in bytes:
                            if char == ' ':
                                nbsp_str.append('&nbsp')
                            else:
                                nbsp_str.append(char)
                        instr.rip_value_ascii = ''.join(nbsp_str)
                    # TODO: there's a bug involving ASCII that cannot be jsonified. To get around
                    # it, we're temporarily pretending they don't exist. Those edge cases need to be
                    # handled.
                    # see typeName(
                    else:
                        instr.rip_value_ascii = "under construction..."
        return disassembled

    except CsError as e:
        print("ERROR: %s" %e)

# class CsInsn exposes all the internal informaion about the disassembled 
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
            row['rip-offset'] = i.rip_offset
            row['rip-resolved'] = i.rip_resolved
            row['rip-value-ascii'] = i.rip_value_ascii
            row['rip-value-hex'] = i.rip_value_hex
        if i.jump:
            row['jump'] = True
            row['jump-address'] = i.jump_address
            row['jump-function-name'] = i.jump_function_name
            row['jump-function-address'] = i.jump_function_address
            row['jump-function-offset'] = i.jump_function_offset
            row['jump-function-size'] = i.jump_function_size
        if i.comment:
            row['comment'] = i.comment
        if i.nop:
            row['nop'] = True
        ret.append(row)
    return ret
