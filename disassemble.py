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

from capstone import Cs, CsError, CS_ARCH_X86, CS_MODE_64, x86
import executable
from demangler import demangle
from os import listdir
from os.path import isfile, join
import datetime
from html_parser import get_short_desc
import json

# Maps an instruction mnemonic to the file that documents it
instr_docfile_map = None

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
                        symbol = executable.ex.get_symbol_by_addr(dest_addr)
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
            for op in instr.operands:
                # Handle rip-relative operands
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
            # what registers does this instruction read/write?
            instr.regs_write_names = [instr.reg_name(reg) for reg in instr.regs_write]
            instr.regs_read_names = [instr.reg_name(reg) for reg in instr.regs_read]
            # Add in documentation meta-data
            instr.docfile = doc_file(instr)
            instr.short_desc = get_short_desc(instr)
            if instr.docfile is None:
                with open('missing_docs.log', 'a+') as f:
                    f.write('[{}] : {}\n'.format(str(datetime.datetime.now()), instr.mnemonic))
        return disassembled

    except CsError as e:
        print("ERROR: %s" %e)

def doc_file(instr):
    instr_map = get_instr_map()
    mnemonic = instr.mnemonic.lower()
    if mnemonic in instr_map:
        return instr_map[mnemonic]
    # Conditional jump instructions have a special page of documentation
    elif instr.group(x86.X86_GRP_JUMP):
        return instr_map['jcc']
    # Conditional move instructions have a special page of documentation
    elif instr.group(x86.X86_GRP_CMOV):
        return instr_map['cmovcc']
    # Conditional set instructions have a special page of documentation
    elif instr.mnemonic[:3] == 'set':
        return instr_map['setcc']
    # Conditional loop instructions have a special page of documentation
    elif instr.mnemonic[:4] == 'loop':
        return instr_map['loopcc']
    # Conditional fcmov instructions have a special page of documentation
    elif instr.mnemonic[:5] == 'fcmov':
        return instr_map['fcmovcc']
    # Instructions that start with 'v' may be vex-encoded, and so the 'v' should be stripped out
    elif instr.mnemonic[0] == 'v':
        return instr_map[mnemonic[1:]]
    else:
        return None

# Returns instr_docfile_map, instantiating it if necessary.
# instr_docfile_map is a mapping of an instruction mnemonic to the file that documents it
def get_instr_map():
    global instr_docfile_map
    if instr_docfile_map is None:
        instr_docfile_map = {}
        dir_path = 'static/inst_ref'
        # http://stackoverflow.com/questions/3207219/how-to-list-all-files-of-a-directory-in-python
        filelist = [f for f in listdir(dir_path) if isfile(join(dir_path, f))]
        for f in filelist:
            filename = f[:-5].lower()
            if ':' in filename:
                names = filename.split(':')
                for name in names:
                    instr_docfile_map[name] = f
            else:
                instr_docfile_map[filename] = f
    return instr_docfile_map

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
            "short_description": i.short_desc
            # "bytes": i.bytes # json can't serialize byte array
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

        # reading/writing registers'
        row['regs_write'] = i.regs_write_names
        row['regs_read'] = i.regs_read_names
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
