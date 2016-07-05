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
from demangler import demangle

"""
Base class for executables
"""
class Executable(object):
    def __init__(self, f):
        self.f = f

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
    def get_function_line_info(self, begin, size):
        print hex(begin), hex(size)
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
                info.append((hex(entry.state.address), entry.state.line, filename))

            elif entry.state.address > (begin + size):
                return info
        return info

    # get line info for given address
    def get_addr_line_info(self, address):
        CU_offset = self.aranges.cu_offset_at_addr(address)
        CU = self.dwarff._parse_CU_at_offset(CU_offset)
       
        lineprog = self.dwarff.line_program_for_CU(CU)
        prevstate = None
        for entry in lineprog.get_entries():
            # We're interested in those entries where a new state is assigned
            if entry.state is None or entry.state.end_sequence:
                continue
            # Looking for a range of addresses in two consecutive states that
            # contain the required address.
            if prevstate and prevstate.address <= address < entry.state.address:
                filename = lineprog['file_entry'][prevstate.file - 1].name
                line = prevstate.line
                return {"filename": filename, "line":line}
            prevstate = entry.state

        return {}

    # general helpers; may or may not be useful
    def get_all_sections(self):
        for sec in self.elff.iter_sections():
            print sec["sh_type"] + ", name: " + str(sec["sh_name"])


"""
Mach-o executable
"""
class MachoExecutable(Executable):
    def __init__(self, f):
        super(MachoExecutable, self).__init__(f)

