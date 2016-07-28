# Copyright 2016 MongoDB Inc.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#    http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from capstone import Cs, CsError, CS_ARCH_X86, CS_MODE_64, x86, CS_OPT_SYNTAX_ATT
import executable
from demangler import demangle
from os import listdir
from os.path import isfile, join
import datetime
from documentation import get_documentation
import json
from binascii import hexlify

# given a sequence of bytes and an optional offset within the file (for display
# purposes) return assembly for those bytes
def disasm(bytes, offset=0):
    print "offset %i" % offset
    try:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        disassembled = list(md.disasm(bytes, offset))
        for i, instr in enumerate(disassembled):
            print "0x%x:\t%s\t%s" % (instr.address, instr.mnemonic, instr.op_str)
            # Handle no-op instructions
            if instr.id == x86.X86_INS_NOP:
                instr.nop = True
            # Handle jump/call instructions
            if instr.group(x86.X86_GRP_JUMP) or instr.group(x86.X86_GRP_CALL):
                # We can only decode the destination if it's an immediate value
                if instr.operands[0].type == x86.X86_OP_IMM:
                    # Ignore if it's a jump/call to an address within this function
                    func_start_addr = disassembled[0].address
                    func_end_addr = disassembled[len(disassembled)-1].address
                    dest_addr = instr.operands[0].imm
                    if func_start_addr <= dest_addr <= func_end_addr:
                        instr.internal_jump = True
                        instr.jump_address = dest_addr
                    else:
                        symbol, field_name = executable.ex.get_symbol_by_addr(
                            dest_addr, 
                            instr.address)
                        if symbol:
                            text_sect = executable.ex.elff.get_section_by_name('.text')
                            sect_addr = text_sect['sh_addr']
                            sect_offset = text_sect['sh_offset']
                            
                            instr.external_jump = True
                            instr.jump_address = dest_addr
                            instr.jump_function_name = demangle(symbol.name)
                            instr.jump_function_address = dest_addr
                            instr.jump_function_offset = dest_addr - sect_addr + sect_offset
                            instr.jump_function_size = symbol['st_size']
                            instr.comment = demangle(symbol.name)

            # Handle individual operands
            c = -1
            instr.regs_explicit = []
            # instr.regs_write_explicit = []
            # instr.regs_read_explicit = []
            for op in instr.operands:
                c += 1
                # Handle rip-relative operands
                if op.type == x86.X86_OP_MEM and op.mem.base == x86.X86_REG_RIP:
                    instr.rip = True
                    instr.rip_offset = op.mem.disp
                    instr.rip_resolved = disassembled[i+1].address + instr.rip_offset
                    symbol, field_name = executable.ex.get_symbol_by_addr(
                        instr.rip_resolved, 
                        instr.address,
                        get_sub_symbol=True)
                    if symbol:
                        instr.comment = demangle(symbol.name)

                        # field_name = executable.ex.get_member_name(
                        #     symbol.name.split(':')[-1],
                        #     instr.address,
                        #     isntr.rip_resolved - symbol['st_value'])
                        if field_name:
                            instr.comment += '.' + field_name
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
                # Handle explicitly read/written registers
                if op.type == x86.X86_OP_MEM and op.mem.base != x86.X86_REG_RIP:
                    ptr = []
                    instr.regs_ptr_explicit = []
                    if op.value.mem.base != 0:
                        regname = instr.reg_name(op.value.mem.base)
                        ptr.append(regname)
                        instr.regs_ptr_explicit.append(regname)
                    if op.value.mem.index != 0:
                        regname = instr.reg_name(op.value.mem.index)
                        ptr.append(regname)
                        instr.regs_ptr_explicit.append(regname)
                    if op.value.mem.disp != 0:
                        ptr.append(hex(op.value.mem.disp))

                    instr.ptr = " ".join(ptr)
                    instr.regs_explicit.append(instr.ptr)
                elif op.type == x86.X86_OP_REG:
                    instr.regs_explicit.append(instr.reg_name(op.value.reg))
                else:
                    instr.regs_explicit.append("")

            # what registers does this instruction read/write?
            instr.regs_write_implicit = [instr.reg_name(reg) for reg in instr.regs_write]
            if instr.group(x86.X86_GRP_CALL) and instr.reg_name(x86.X86_REG_RAX) not in instr.regs_write_implicit:
                instr.regs_write_implicit.append(instr.reg_name(x86.X86_REG_RAX))
            instr.regs_read_implicit = [instr.reg_name(reg) for reg in instr.regs_read]
            # Add in documentation meta-data
            instr.short_desc, instr.docfile = get_documentation(instr)
            if instr.docfile or instr.short_desc is None:
                with open('missing_docs.log', 'a+') as f:
                    f.write('[{}] : {}\n'.format(str(datetime.datetime.now()), instr.mnemonic))
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
            "docfile": i.docfile,
            "short_description": i.short_desc,
            "bytes": hexlify(i.bytes)
        }

        # If this instruction contains a rip-relative address, then assign the relevant data
        if i.rip:
            row['rip'] = True
            row['rip-offset'] = i.rip_offset
            row['rip-resolved'] = i.rip_resolved
            row['rip-value-ascii'] = i.rip_value_ascii
            row['rip-value-hex'] = i.rip_value_hex
        if i.internal_jump: 
            row['internal-jump'] = True
            row['jump-address'] = hex(i.jump_address)
        if i.external_jump:
            row['external-jump'] = True
            row['jump-function'] = i.jump_function
            row['jump-address'] = i.jump_address
            row['jump-function-name'] = i.jump_function_name
            row['jump-function-address'] = i.jump_function_address
            row['jump-function-offset'] = i.jump_function_offset
            row['jump-function-size'] = i.jump_function_size
        if i.comment:
            row['comment'] = i.comment
        if i.nop:
            row['nop'] = True

        # reading/writing registers
        row['ptr'] = i.ptr
        row['regs_write_explicit'] = []
        row['regs_read_explicit'] = [] if not i.regs_ptr_explicit else i.regs_ptr_explicit
        with open('x86operands.json', 'r') as fp:
            op_data = json.load(fp)
        try:
            readwrites = op_data[i.mnemonic][str(len(i.regs_explicit))]
            for rw, reg in zip(readwrites, i.regs_explicit):
                if reg != "" and rw == 'W':
                    row['regs_write_explicit'].append(reg)
                elif reg != "" and rw == 'R':
                    row['regs_read_explicit'].append(reg)
                elif reg != "" and rw == 'X':
                    row['regs_write_explicit'].append(reg)
                    row['regs_read_explicit'].append(reg)
        except:
            pass

        row['regs_write_implicit'] = i.regs_write_implicit
        row['regs_read_implicit'] = i.regs_read_implicit
        with open('x86registers.json', 'r') as fp:
            reg_data = json.load(fp)
        try:
            row['flags'] = parse_flags(reg_data[i.mnemonic])
        except:
            row['flags'] = {}
            
        ret.append(row)
    return ret

# Given a string of instruction metadata (see x86registers.json)
# return a dict of the affected flags
def parse_flags(flag_str):
    # split string of instruction metadata into an array, and filter out non-flag metadata
    flag_arr = list(filter(lambda x: '=' in x, flag_str.split()))
    flags = {}
    for f in flag_arr:
        flag_name = f[0:f.index('=')]
        action = f[f.index('=') + 1:]
        if action == 'X': # both read and write
            flags = upsert('R', flag_name, flags)
            flags = upsert('W', flag_name, flags)
        flags = upsert(action, flag_name, flags)
    return flags

def upsert(key, value, obj):
    if key in obj:
        obj[key].append(value)
    else:
        obj[key] = [value]
    return obj
