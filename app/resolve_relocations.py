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

from disassemble import disasm_plt
from demangler import demangle
from elftools.elf.relocation import RelocationSection
import struct, time

MAX_INSTR_SIZE = 16

def resolve_plt(addr, plt_section, exe):
    sym = None
    plt_offset = addr - plt_section['sh_addr'] + plt_section['sh_offset']
    plt_section.stream.seek(plt_offset)
    # "execute" instructions in .plt to find indirection
    rela_addr, size = disasm_plt(plt_section.stream.read(MAX_INSTR_SIZE), addr)
    if not rela_addr:
        return None

    # update rela_addr if it's in the reloc table
    reloc_section = exe.elff.get_section_by_name(".rela.plt")
    sym = sym_from_reloc_section(exe, rela_addr, reloc_section)
    if sym: # found in reloc table
        sym.name = demangle(sym.name) + " (.plt)"
        return sym

    else: # not in relocation table
        print ("not in reloc table")
        section = exe.get_section_from_offset(rela_addr)
        if section.name == ".text":
            return get_symbol_by_addr(rela_addr)
        else:
            print "Unhandled section: " + section.name
            return None

def resolve_got(addr, got_section, exe):
    # is GOT always populated by .dyn?? unclear. TODO
    reloc_section = exe.elff.get_section_by_name(".rela.dyn")
    sym = sym_from_reloc_section(exe, addr, reloc_section)
    if sym:
        sym.name = demangle(sym.name) + " (.got)"
        return sym

    else:
        print "not in reloc table"
        return None


# given relocation address (the address into .got or .plt)
# and the relevant relocation section, get the symbol
def sym_from_reloc_section(exe, rela_addr, reloc_section):
    symtab = exe.elff.get_section(reloc_section['sh_link'])
    for reloc in reloc_section.iter_relocations():
        if reloc["r_offset"] == rela_addr:
            sym = symtab.get_symbol(reloc['r_info_sym'])
            return sym
    return None


