from elftools.elf.elffile import ELFFile
from elftools.common.py3compat import iteritems
from demangler import demangle

# Get all top-level members of a given DIE
def get_members(die):
    global die_list
    members = []
    for child in die.iter_children():
        if child.tag == 'DW_TAG_member':
            members.append(child)

    if len(members) == 0:
        for attrname, attrval in iteritems(die.attributes):
            if attrval.name == 'DW_AT_type':
                return get_members(die_list[attrval.value])
        return []
    else:
        return members

# Given a list of DW_TAG_member DIE, get the DIE that the offset falls inside of
def get_member_within(members, offset):
    curr_highest_member = None
    curr_highest_offset = None
    for member in members:
        if not member.attributes.get('DW_AT_data_member_location'):
            continue
        if curr_highest_member is None:
            curr_highest_member = member
            curr_highest_offset = member.attributes.get('DW_AT_data_member_location').value
        else:
            member_offset = member.attributes.get('DW_AT_data_member_location').value
            if member_offset <= offset and member_offset > curr_highest_offset:
                curr_highest_member = member
                curr_highest_offset = member_offset
    return (curr_highest_member, curr_highest_offset,)

# A type DIE may or may not contain a DW_AT_byte_size attribute. If it doesn't, then that means
# it inherits its type from the type DIE that it references. This relationship can persist through a
# varible number of references
def get_size_attr(die):
    for attrname, attrval in iteritems(die.attributes):
        if attrname == 'DW_AT_byte_size':
            return attrval.value
        if attrname == 'DW_AT_type':
            subtype = die_list[attrval.value]
    return get_size_attr(subtype)

# elffile : type(ELFFile)
#   File that this symbol belongs to.
# symbol : type(str)
#   Symbol that is referenced by an instruction.
# offset : type(int)
#   Offset into the memory that the symbol occupies.
# addr : type(int)
#   Address that the instruction belongs to.
#   Technically this isn't required, but without it we'd have to search EVERY die. By using the 
#   instruction address, we're able to use the aranges to narrow down our search to a single CU.
def get_sub_symbol(dwarfinfo, top_DIE, symbol, offset, addr):
    global die_list
    die_list = {}

    CU = top_DIE.cu

    for die in CU.iter_DIEs():
        die_list[die.offset - CU.cu_offset] = die

    for die in CU.iter_DIEs():
        if "DW_AT_name" in die.attributes and die.attributes["DW_AT_name"].value == symbol:
            return _get_sub_symbol(die, offset)

# die : type(elftools.dwarf.die.DIE)
#   DIE that represents the symbol we're searching.
# offset : type(int)
#   Offset into the memory that the symbol occupies.
def _get_sub_symbol(die, offset):
    members = get_members(die)
    if len(members) == 0:
        return None

    member_within, member_offset = get_member_within(members, offset)
    if not member_within:
        return None

    # print member_within
    size = get_size_attr(member_within)
    name = member_within.attributes.get('DW_AT_name').value

    if member_offset <= offset < member_offset + size:
        sub_member_name = _get_sub_symbol(member_within, offset - member_offset)
        if sub_member_name is None:
            return name
        else:
            return name + '.' + sub_member_name
    else:
        print "FIELD CANNOT BE FOUND"
        return None
