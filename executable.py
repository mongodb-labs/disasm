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
        MAGIC = ["7f454c46"]

        f.seek(0)
        magic = f.read(4).encode('hex')
        return magic in MAGIC

    @staticmethod
    def isMacho(f):
        MAGIC = ["cffaedfe"]

        f.seek(0)
        magic = f.read(4).encode('hex')
        return magic == "cffaedfe" 

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