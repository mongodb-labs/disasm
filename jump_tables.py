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

import struct
from elftools.common.utils import preserve_stream_pos

TYPE_ADDRESS = "address"
TYPE_OFFSET = "offset"

# get the "index" register where the switch variable is stored
def get_switch_register(instrs):
    for instr in reversed(instrs):
        if "mov" in instr["mnemonic"] and instr.get('ptr') and instr['ptr'][1] != "":
            return instr["ptr"][1]

# Given a list of instructions that terminate in a jmp, return the lea instruction closest to the
# last instruction (aka the jmp) as well as its index
def get_lea(instrs):
    i = len(instrs)
    mnemonic = None
    while mnemonic != "lea":
        i -= 1
        mnemonic = instrs[i]["mnemonic"]

        # check for jmp to a virtual function
        if mnemonic == "mov" and instrs[i].get("ptr") and len(instrs[i]["regs_write_explicit"]) > 0:
            reg_is_written_and_read = instrs[i]["ptr"][0] == instrs[i]["regs_write_explicit"][0]
            try:
                int(instrs[i]["ptr"][2], 16)
                ptr_is_const_offset = True
            except:
                ptr_is_const_offset = False
            if reg_is_written_and_read and ptr_is_const_offset:
                return None, None

        # didn't find lea or virtual function
        if i == 0:
            return None, None

    # found lea with an address
    if instrs[i].get("ptr_address"):
        return instrs[i], i
    else:
        return None, None

# given a list of instructions and the index of the relevant lea, 
# return the jump table's method of addressing (either by offset or by address)
# if the jump table uses offsets to indicate jump locations, also return the offset size
def get_location_method(instrs, lea_index):
    # default is location via direct addressing
    location_method = TYPE_ADDRESS

    # register that is written to by lea
    address_reg = instrs[lea_index]["regs_write_explicit"][0]

    # if jump table uses offsets, the number of bytes in each offset/entry
    offset_size = None
    for instr in instrs[lea_index:]:
        if instr["mnemonic"] == "add" and address_reg in instr["regs_read_explicit"]:
            location_method = TYPE_OFFSET
        if "mov" in str(instr["mnemonic"]) and instr.get("ptr_size"):
            offset_size = int(instr.get("ptr_size"))
    return location_method, offset_size

# given the offset_size for each jump table entry, return the appropriate struct
# upacking format 
def offset_size_to_struct(offset_size):
    if offset_size == 4:
        return "<i" # integer
    elif offset_size == 8:
        print "jump table offset size = " + str(offset_size)
        return "<q" # long long
    else:
        print "jump table offset size = " + str(offset_size)
        return None

# get the address of a certain jump table entry
def get_jump_address(location_method, jt_addr, offset_size, stream):
    struct_format = offset_size_to_struct(offset_size)
    if not struct_format:
        return None

    if location_method == TYPE_OFFSET:
        return jt_addr + struct.unpack(struct_format, stream.read(offset_size))[0]
    elif location_method == TYPE_ADDRESS:
        return struct.unpack(struct_format, stream.read(offset_size))[0]
    else:
        return None

# Entry point of this package
def get_jumptable(instrs, stream, function_start, function_end):
    # get info: jump table start address (jt_addr) and how it is formatted (location_method)
    lea_instr, i = get_lea(instrs)
    if not i:
        return None
    jt_addr = lea_instr["ptr_address"]
    location_method, offset_size = get_location_method(instrs, i)

    # get entries
    with preserve_stream_pos(stream):
        stream.seek(jt_addr)
        jmp_addr = get_jump_address(location_method, jt_addr, offset_size, stream)
        jmp_index = 0

        # maps the jumpTo address x to an array of the jump table indexes that map to x
        jumps = {}
        prev_jmp_addr = -1
        while function_start <= jmp_addr <= function_end:
            jumps = upsert(jumps, hex(jmp_addr), jmp_index, hex(prev_jmp_addr))
            prev_jmp_addr = jmp_addr
            jmp_addr = get_jump_address(location_method, jt_addr, offset_size, stream)
            jmp_index += 1

    # format jumps
    res = []
    for addr in jumps:
        res.append({"address": addr, "indices": jumps[addr]})
    res.sort(key=lambda x: x["indices"][0]) # strings (aka ranges) will be last
    return res

def upsert(jumps, jmp_addr, jmp_index, prev_jmp_addr):
    if jmp_addr in jumps and jmp_addr == prev_jmp_addr:
        # replace last entry with a string to indicate range; 
        # keep building on string if same jmp_addr keeps coming up
        index_arr = str(jumps[jmp_addr][-1]).split("-")
        if len(index_arr) == 1:
            index_arr.append(str(jmp_index))
        elif len(index_arr) == 2:
            index_arr[1] = str(jmp_index)
        jumps[jmp_addr][-1] = "-".join(index_arr)
    elif jmp_addr in jumps:
        jumps[jmp_addr].append(jmp_index)
    else:
        jumps[jmp_addr] = [jmp_index]
    return jumps

