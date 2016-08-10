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

import sys
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.dwarf.descriptions import describe_form_class
from elftools.dwarf.die import DIE
from demangler import demangle
from bisect import bisect_right
from symbol_lookup import get_sub_symbol
from dwarf_expr import describe_DWARF_expr, set_global_machine_arch, OpPiece
import jump_tables as jt
from die_information import DIEInformation

"""
Base class for executables
"""
class Executable(object):
    def __init__(self, f):
        self.f = f
        self._symbol_addr_map = None

    @staticmethod
    def isElf(f):
        MAGIC = ["7f454c46", "464c457f"]

        f.seek(0)
        magic = f.read(4).encode('hex')
        return magic in MAGIC

    @staticmethod
    def isMacho(f):
        MAGIC = ["cffaedfe", "feedfacf"]

        f.seek(0)
        magic = f.read(4).encode('hex')
        return magic in MAGIC

    def raise_not_implemented(self):
        raise NotImplementedError("Class %s doesn't implement a method" 
            % (self.__class__.__name__))

    # given starting offset (relative to file), return n bytes
    def get_bytes(self, start, n):
        self.raise_not_implemented()

    # return list of all functions in executable in the form
    # { "offset": "", "size": "", "name": "" }
    def get_all_functions(self):
        self.raise_not_implemented()

    def get_symbol_by_addr(self, addr):
        self.raise_not_implemented()

    def get_data_as_cstring(self, file_offset):
        self.raise_not_implemented()

"""
ELF executable
"""
class ElfExecutable(Executable):
    def __init__(self, f):
        super(ElfExecutable, self).__init__(f)
        self.elff = ELFFile(self.f)
        if self.elff.has_dwarf_info():
            self.dwarff = self.elff.get_dwarf_info()
            self.aranges = self.dwarff.get_aranges()
        else:
            self.dwarff = None
            self.aranges = None

        self.CU_offset_to_DIE = {}
        # { addr -> { type -> die } }
        self.type_dies = {}

    def get_bytes(self, start, n):
        self.f.seek(start)
        return self.f.read(n)

    def get_all_functions(self):
        function_syms = self.get_function_syms()

        # get offset and beginning of .text section
        # *** currently assuming all functions always in .text TODO!!!!!!!!!!!
        # there are some symbols that cause the offset to go negative so yeah let's fix that
        section = self.elff.get_section_by_name(".text")

        functions = []
        #  load info for each symbol into functions[]
        for sym in function_syms:
            func = {}
            func["offset"] = sym["st_value"] - section["sh_addr"] + section["sh_offset"]
            func["st_value"] = sym["st_value"]
            func["size"] = sym["st_size"]
            func["name"] = demangle(sym.name)
            functions.append(func)
        return functions

    # get all the symbols that correspond to functions
    def get_function_syms(self):
        symtab = self.elff.get_section_by_name(".symtab")
        function_syms = list(filter(lambda sym: sym["st_info"]["type"] == "STT_FUNC", symtab.iter_symbols()))
        return function_syms

    # get the line info for a given function, whose addresses are
    # bound by begin and begin+size
    # ret is a list of (addr, filename, line)
    def get_function_line_info(self, begin, size):
        info = []

        CU_offset = self.aranges.cu_offset_at_addr(begin)
        CU = self.dwarff._parse_CU_at_offset(CU_offset)
        lineprog = self.dwarff.line_program_for_CU(CU)
        for entry in lineprog.get_entries():
            # We're interested in those entries where a new state is assigned
            if entry.state is None or entry.state.end_sequence:
                continue

            # Looking for all addresses in [begin, begin + size]
            if begin <= entry.state.address < (begin + size):
                filename = lineprog['file_entry'][entry.state.file - 1].name
                info.append((hex(entry.state.address), filename, entry.state.line))

            elif entry.state.address > (begin + size):
                return info
        return info

    # utility to get the first DIE in the CU the given address points to
    def _get_top_DIE(self, address):
        if not self.dwarff:
            return None
            
        CU_offset = self.aranges.cu_offset_at_addr(address)
        CU = self.dwarff._parse_CU_at_offset(CU_offset)
        # preload tree of DIEs
        if not CU_offset in self.CU_offset_to_DIE:
            self.CU_offset_to_DIE[CU_offset] = CU.get_top_DIE() # save
        
        return self.CU_offset_to_DIE[CU_offset]

    # given a cu and an offset, return the DIE object at that offset
    def _parse_DIE_at_offset(self, cu, die_offset):
        die = DIE(
                cu=cu,
                stream=cu.dwarfinfo.debug_info_sec.stream,
                offset=die_offset + cu.cu_offset)
        return die

    # given a DIE object, get its name
    def _get_DIE_name(self, die):
        CU = die.cu

        if "DW_AT_name" in die.attributes:
            return die.attributes["DW_AT_name"].value
        while "DW_AT_abstract_origin" in die.attributes:
            die = self._parse_DIE_at_offset(CU, die.attributes["DW_AT_abstract_origin"].value)
            if "DW_AT_name" in die.attributes:
                return die.attributes["DW_AT_name"].value
        return None

    # given a CU and the offset of the class/struct/union type DIE, get its member DIEs
    def _get_obj_members(self, CU, offset):
        objTags = ["DW_TAG_structure_type", "DW_TAG_union_type", "DW_TAG_class_type"]
        rabbitHoleTags = ["DW_TAG_inheritance", "DW_TAG_member"]

        members = []
        for die in CU.iter_DIEs():
            if die.tag in objTags and die.offset == offset:
                for child in die.iter_children():
                    # recursively get parent class info, if available
                    if child.tag in rabbitHoleTags and "DW_AT_type" in child.attributes:
                        type_die = self._parse_DIE_at_offset(child.cu, child.attributes["DW_AT_type"].value)
                        members += self._get_obj_members(type_die.cu, type_die.offset)
                    if child.tag == "DW_TAG_member":
                        members.append(child)
        return members

    def _get_obj_member_info(self, CU, offset):
        members = self._get_obj_members(CU, offset)

        memberInfo = {}
        for member in members:
            memberAttrs = member.attributes 
            if "DW_AT_name" in memberAttrs and "DW_AT_data_member_location" in memberAttrs:
                memberInfo[memberAttrs["DW_AT_data_member_location"].value] = memberAttrs["DW_AT_name"].value
        return memberInfo

    def get_obj_members(self, address):
        top_DIE = self._get_top_DIE(address)
        if top_DIE == None:
            return None
        CU = top_DIE.cu

        # get function (subprogram) DIE
        parent = None
        for die in top_DIE.iter_children():
            if self._addr_in_DIE(die, address) and die.tag == "DW_TAG_subprogram":
                parent = die

        if parent == None: 
            return None

        function_children = self._die_variables(parent, [])
        name2member = {}
        for die in function_children:
            name =  self._get_DIE_name(die)
            while "DW_AT_type" in die.attributes:
                nextDie = self._parse_DIE_at_offset(die.cu, die.attributes["DW_AT_type"].value)
                die = nextDie
                if die.tag == "DW_TAG_class_type":
                    name2member[name] = self._get_obj_member_info(CU, die.offset)
        return name2member

    # get the dies of the variables "owned" by the given parent
    def _die_variables(self, parent, children=[]):
        for child in parent.iter_children():
            children.append(child)
            if child.tag == "DW_TAG_lexical_block":
                children = self._die_variables(child, children)
        return children

    # a helper function for get_function_reg_contents;
    # add the given location piece to the reg_contents accumulator 
    def _update_reg_contents(self, reg_contents, begin_addr, end_addr, loc_pieces, name):
        for piece in loc_pieces:
            # sometimes it's just a const??? why????
            if not isinstance(piece, OpPiece):
                continue
            # there are rare cases when there will be multiple registers per variable location piece
            # for ease, we convert all registers into an array
            regs = [piece.key] if not isinstance(piece.key, list) else piece.key
            for reg in regs:
                if reg not in reg_contents:
                    reg_contents[reg] = []

                piece_size = 0 if not piece.size else piece.size
                reg_contents[reg].append({
                    "start": begin_addr,
                    "end": end_addr,
                    "name": name,
                    "value": piece.value,
                    "size": piece.size,
                    });
        return reg_contents

    # get the mappings of registers -> variables, where available, in the given function
    def get_function_reg_contents(self, address):
        top_DIE = self._get_top_DIE(address)
        if top_DIE == None:
            return None
        CU = top_DIE.cu

        # get function (subprogram) DIE
        parent = None
        for die in top_DIE.iter_children():
            if self._addr_in_DIE(die, address) and die.tag == "DW_TAG_subprogram":
                parent = die

        if parent == None: 
            return None

        set_global_machine_arch(self.elff.get_machine_arch())

        # we are only interested in dies that have a location attribute
        reg_contents = {}
        function_children = self._die_variables(parent, [])
        loc_dies = [die for die in function_children if "DW_AT_location" in die.attributes]
        location_lists = self.dwarff.location_lists()
        for die in loc_dies:
            loc_attributes = die.attributes["DW_AT_location"]
            name = self._get_DIE_name(die)
            if name is None:
                name = id(name)

            # create mapping of register -> location and corresponding variable name
            if loc_attributes.form == "DW_FORM_exprloc":
                loc_pieces = describe_DWARF_expr(loc_attributes.value, CU.structs)
                if loc_pieces is None:
                    continue
                reg_contents = self._update_reg_contents(reg_contents, "", "", loc_pieces, name)
            elif loc_attributes.form == "DW_FORM_sec_offset":
                loclist = location_lists.get_location_list_at_offset(loc_attributes.value)
                for loc in loclist:
                    loc_pieces = describe_DWARF_expr(loc.loc_expr, CU.structs)
                    if loc_pieces is None:
                        continue
                    reg_contents = self._update_reg_contents(reg_contents, 
                        hex(loc.begin_offset), hex(loc.end_offset), loc_pieces, name)       
        return reg_contents


    # is the given address contained in the given DIE?
    def _addr_in_DIE(self, DIE, address):
        if "DW_AT_ranges" in DIE.attributes:
            offset = DIE.attributes["DW_AT_ranges"].value
            range_lists = self.dwarff.range_lists()
            ranges = range_lists.get_range_list_at_offset(offset)
            for entry in ranges:
                # RangeEntry = (begin_offset, end_offset)
                if entry[0] <= address < entry[1]:
                    return True
            return False
        elif "DW_AT_low_pc" in DIE.attributes and "DW_AT_high_pc" in DIE.attributes:
            lo = int(DIE.attributes["DW_AT_low_pc"].value)
            high_pc = DIE.attributes["DW_AT_high_pc"]
            highpc_attr_class = describe_form_class(high_pc.form)
            if highpc_attr_class == 'address':
                hi = int(high_pc.value)
            elif highpc_attr_class == 'constant':
                hi = lo + int(high_pc.value)       
            else:
                print('Error: invalid DW_AT_high_pc class:', highpc_attr_class)
            return lo <= address < hi
        elif "DW_AT_low_pc" in DIE.attributes:
            lo = int(DIE.attributes["DW_AT_low_pc"].value)
            return address == lo

    # helper function to get array of DIEs for given address
    def _get_addr_DIEs(self, parent, address, stack):
        for child in parent.iter_children():
            # proceed if child is in the right range
            if self._addr_in_DIE(child, address):
                stack.append(child)
                return self._get_addr_DIEs(child, address, stack)
        return stack

    # get line info for given address
    # return (filepath, line)
    def _get_addr_line_info(self, address, lineprog=None):
        if not self.dwarff:
            return None
        
        if lineprog == None:
            CU_offset = self.aranges.cu_offset_at_addr(address)
            CU = self.dwarff._parse_CU_at_offset(CU_offset)
            lineprog = self.dwarff.line_program_for_CU(CU)
        
        prevstate = None
        res = (None, None)
        minDiff = sys.maxint
        # get the most narrow line entry program
        for entry in lineprog.get_entries():
            if entry.state is None or entry.state.end_sequence:
                continue
            # prev and cur states encompass the address we're looking for
            if (prevstate and prevstate.address <= address < entry.state.address 
                and address - prevstate.address < minDiff):
                file_entry = lineprog['file_entry'][prevstate.file - 1]
                filepath = (lineprog["include_directory"][file_entry.dir_index - 1] 
                    + "/" 
                    + file_entry.name)
                res = (filepath, prevstate.line)
                minDiff = address - prevstate.address
            prevstate = entry.state
        return res

    def _die_to_function(self, die):
        while "DW_AT_name" not in die.attributes:
            if "DW_AT_abstract_origin" in die.attributes:
                ref_attr = "DW_AT_abstract_origin"
            elif "DW_AT_specification" in die.attributes:
                ref_attr = "DW_AT_specification"
            else:
                break
            new_offset = (int(die.attributes[ref_attr].value) + die.cu.cu_offset)
            die = DIE(cu=die.cu, stream=die.stream, offset=new_offset)
        if "DW_AT_name" in die.attributes:
            return die.attributes["DW_AT_name"].value
        else:
            return None

    # get array of DIEs for given address
    def get_addr_stack_info(self, address):
        top_DIE = self._get_top_DIE(address)
        if top_DIE == None:
            return None
        CU = top_DIE.cu

        # stack[0] is the parent-est
        stack = self._get_addr_DIEs(top_DIE, address, [])

        # put in jsonifiable form of [{filepath, line, function name}, ...]
        # function info is offset by one entry (because we want enclosing function)
        # we're not using dwarfinfo.line_program_for_CU because it re-parses all DIEs
        
        if 'DW_AT_stmt_list' in top_DIE.attributes:
            lineprog = self.dwarff._parse_line_program_at_offset(
                top_DIE.attributes['DW_AT_stmt_list'].value, CU.structs)
        else:
            return None

        res = []
        prev = stack[0]
        for entry in stack[1:]:
            if "DW_AT_decl_file" in entry.attributes:
                file_AT = "DW_AT_decl_file"
                line_AT = "DW_AT_decl_line"
            elif "DW_AT_call_file" in entry.attributes:
                file_AT = "DW_AT_call_file"
                line_AT = "DW_AT_call_line"
            else:
                print "No valid file number"
                continue
            fileno = entry.attributes[file_AT].value
            file_entry = lineprog['file_entry'][fileno - 1]
            filepath = (lineprog["include_directory"][file_entry.dir_index - 1] 
                    + "/" 
                    + file_entry.name)
            function_name = self._die_to_function(prev)
            res.append((filepath, entry.attributes[line_AT].value, function_name))
            prev = entry

        # append uppermost "level" of info if not already included in DIE stack
        filepath_last, fileno_last = self._get_addr_line_info(address, lineprog)
        if len(res) > 0 and fileno_last == fileno and filepath_last == filepath:
            return res
        function_name_last = self._die_to_function(prev)
        res.append((filepath_last, fileno_last, function_name_last))
        return res


    # general helpers; may or may not be useful
    def get_all_sections(self):
        for sec in self.elff.iter_sections():
            print sec["sh_type"] + ", name: " + str(sec["sh_name"])

    # Returns the symbol that a particular address maps to, if applicable.
    #
    # If get_sub_symbol is true, then this function will also attempt to determine the "sub" symbol
    # of this address. That is, if the object at that address is a class, struct, union, etc., then
    # the member variable can also be determined in a reasonable amount of time using dwarf and 
    # aranges
    #
    # symbol_addr : <int>
    #   Memory address in question
    # instr_addr : <int>
    #   Address of the instruction that references symbol_addr
    # gets_ub_symbol: <bool>
    #   True if the program should look for the "sub" symbol, False otherwise.
    #   Functions do not have "sub" symbols, so this lookup is costly and pointless in this case.
    #
    # Returns a 2-tuple:
    #   (symbol_name, sub_symbol)
    #   sub_symbol will always be None if get_sub_symbol is false or if .dwarf_info or 
    #   .dwarf_aranges doesn't exist
    def get_symbol_by_addr(self, symbol_addr, instr_addr, get_sub_symbol=False):
        symtab = self.elff.get_section_by_name('.symtab')
        if self._symbol_addr_map is None:
            self._symbol_addr_map = list(symtab.iter_symbols())
            self._symbol_addr_map.sort(key=lambda symbol: symbol.entry['st_value'])
            self._symbol_addr_map_keys = [symbol.entry['st_value'] for symbol in self._symbol_addr_map]
        index = bisect_right(self._symbol_addr_map_keys, symbol_addr) - 1
        sym = self._symbol_addr_map[index]
        if sym.entry['st_value'] <= symbol_addr < (sym.entry['st_value'] + sym.entry['st_size']):
            if get_sub_symbol:
                member_name = self.get_sub_symbol_by_offset(
                    demangle(sym.name).split(':')[-1], 
                    symbol_addr - sym.entry['st_value'], 
                    instr_addr)
                return (sym, member_name,)
            else:
                return (sym, None)
        else:
            return (None, None)

    def get_sub_symbol_by_offset(self, symbol_name, offset, instr_addr):
        if self.dwarff is None or self.aranges is None:
            return None
        return get_sub_symbol(
            self.dwarff,
            self.aranges,
            symbol_name,
            offset,
            instr_addr)

    def get_data_as_cstring(self, file_offset):
        cstring = ""
        index = 0
        curr_byte = self.get_bytes(file_offset, 1)
        while curr_byte != '\x00':
            cstring += curr_byte
            index += 1
            if index > 128:
                break
            curr_byte = self.get_bytes(file_offset + index, 1)
        print repr(cstring)
        print index
        return repr(cstring)

    def get_jumptable(self, instrs, functionStart, functionEnd):
        return jt.get_jumptable(instrs, self.f, functionStart, functionEnd)

    def get_jumptable_switch_reg(self, instrs):
        return jt.get_switch_register(instrs)

    # Returns a dict of type names to type information, or None if .dwarf_info or .dwarf_aranges is
    # not available
    def get_type_info(self, addr):
        if self.dwarff is None or self.aranges is None:
            return None
        CU_offset = self.aranges.cu_offset_at_addr(addr)
        CU = self.dwarff._parse_CU_at_offset(CU_offset)

        # WARNING: THIS IS WRONG.
        # Currently, this assumes that if type_dies is not None, then it's correct. This may not be
        # true when a new function from a different CU is loaded. Please please please handle this.
        if self.type_dies.get(addr) is not None:
            return self.type_dies.get(addr)

        # self.type_dies = {}
        type_dies = {}
        for die in CU.iter_DIEs():
            # For some reason, some die tags are ints...
            if type(die.tag) is str and 'type' in die.tag:
                dieInfo = DIEInformation(die)
                if dieInfo:
                    # self.type_dies.append(dieInfo)
                    type_dies[dieInfo['name']] = dieInfo
        self.type_dies[addr] = type_dies
        return type_dies

"""
Mach-o executable
"""
class MachoExecutable(Executable):
    def __init__(self, f):
        super(MachoExecutable, self).__init__(f)

