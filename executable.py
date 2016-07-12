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

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.dwarf.descriptions import describe_form_class
from elftools.dwarf.die import DIE
from demangler import demangle
from bisect import bisect_right

## the (global) executable we're looking at
ex = None

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
            if begin <= entry.state.address <= (begin + size):
                filename = lineprog['file_entry'][entry.state.file - 1].name
                info.append((hex(entry.state.address), filename, entry.state.line))

            elif entry.state.address > (begin + size):
                return info
        return info

    # is the given address contained in the given DIE?
    def _addr_in_DIE(self, DIE, address):
        if "DW_AT_ranges" in DIE.attributes:
            offset = DIE.attributes["DW_AT_ranges"].value
            range_lists = self.dwarff.range_lists()
            ranges = range_lists.get_range_list_at_offset(offset)
            for entry in ranges:
                # RangeEntry = (begin_offset, end_offset)
                if entry[0] <= address <= entry[1]:
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
            return lo <= address <= hi

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
        if lineprog == None:
            CU_offset = self.aranges.cu_offset_at_addr(address)
            CU = self.dwarff._parse_CU_at_offset(CU_offset)
            lineprog = self.dwarff.line_program_for_CU(CU)
        
        prevstate = None
        for entry in lineprog.get_entries():
            if entry.state is None or entry.state.end_sequence:
                continue
            # prev and cur states encompass the address we're looking for
            if prevstate and prevstate.address <= address <= entry.state.address:
                file_entry = lineprog['file_entry'][prevstate.file - 1]
                filepath = (lineprog["include_directory"][file_entry.dir_index - 1] 
                    + "/" 
                    + file_entry.name)
                return (filepath, prevstate.line)
            prevstate = entry.state
        return None # addr not found in lineprog

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
        CU_offset = self.aranges.cu_offset_at_addr(address)
        CU = self.dwarff._parse_CU_at_offset(CU_offset)
        # preload tree of DIEs
        if CU_offset in self.CU_offset_to_DIE:
            top_DIE = self.CU_offset_to_DIE[CU_offset]
        else:
            top_DIE = CU.get_top_DIE()
            self.CU_offset_to_DIE[CU_offset] = top_DIE # save
        
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

    def get_symbol_by_addr(self, addr):
        symtab = self.elff.get_section_by_name('.symtab')
        if self._symbol_addr_map is None:
            self._symbol_addr_map = list(symtab.iter_symbols())
            self._symbol_addr_map.sort(key=lambda symbol: symbol.entry['st_value'])
            self._symbol_addr_map_keys = [symbol.entry['st_value'] for symbol in self._symbol_addr_map]
        index = bisect_right(self._symbol_addr_map_keys, addr) - 1
        sym = self._symbol_addr_map[index]
        print addr
        print sym.entry['st_value']
        print sym.entry['st_size']
        print [symbol.entry['st_value'] for symbol in self._symbol_addr_map[index-3:index+3]]
        if sym.entry['st_value'] <= addr < (sym.entry['st_value'] + sym.entry['st_size']):
            print "Returning", sym.name, "as matched symbol"
            return demangle(sym.name)
        else:
            print "Could not match address"
            return None

"""
Mach-o executable
"""
class MachoExecutable(Executable):
    def __init__(self, f):
        super(MachoExecutable, self).__init__(f)

