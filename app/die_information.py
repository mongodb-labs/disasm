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

from elftools.dwarf.die import DIE

from dwarf_expr import describe_DWARF_expr

# Maps of each DIE offset to the corresponding DIE.
# Used when trying to follow DIE type references, i.e., a DW_TAG_typedef DIE that has a DW_AT_type
# attribute that refers to a DW_TAG_base_type DIE.
die_list = {}

# Maps a DWARF tag to the modifier symbol that represents it.
# May be incomplete. Will be filled in as missing cases are found.
tag_modifier_map = {
    'DW_TAG_pointer_type': '*',
    'DW_TAG_const_type': 'const',
    'DW_TAG_reference_type': '&',
    'DW_TAG_array_type': '[]',
}

# Clears the die then maps each DIE offset to the corresponding DIE.
def reset_die_list(cu):
    global die_list
    # Would it be better to do die_list.clear()?
    die_list = {}
    try:
        # TODO: This process breaks around DIE-offset 1093103
        # See https://github.com/eliben/pyelftools/issues/112 for more information
        # For now we will stop the process altogether if the DIE tree cannot be fully parsed.
        # Realistically, however, the program should be able to return a partial solution on partial
        # success, instead of completely failing.
        for die in cu.iter_DIEs():
            die_list[die.offset] = die
        return True
    except:
        return False

class MemberInformation(dict):
    def __init__(self, name, type, depth, offset, modifiers=None):
        return dict.__init__(self,
            name=name,
            type=type,
            depth=depth,
            offset=offset,
            modifiers=modifiers,)

    @staticmethod
    def member(child, depth, offset):
        global die_list

        name = None
        typeName = None

        if child.attributes.get('DW_AT_name'):
            name = child.attributes.get('DW_AT_name').value
        elif isType(child, 'DW_TAG_union_type'): 
            name = "(anonymous union)"
        else:
            name = "Cannot find the name of this member"

        if child.attributes.get('DW_AT_type'):
            typeRef = child.attributes.get('DW_AT_type').value
            childType = die_list[child.cu.cu_offset + typeRef]
            typeName, modifiers = getTypeAndModifiers(childType)
        else:
            typeName = None
            modifiers = None

        # member offset
        offsetAttr = child.attributes.get('DW_AT_data_member_location')
        if child.attributes.get('DW_AT_external'):
            # If a child is external, then it's not an instance variable, so we don't care. Return
            # None and handle this in the next level up.
            return None
        elif offsetAttr and offset is not None:
            offset += offsetAttr.value 
        else:
            offset = None
        
        return MemberInformation(
            name, 
            typeName, 
            depth, 
            offset,
            modifiers)

    # Creates a MemberInformation dict for a DIE that's known to be the parent of another DIE.
    # The only real difference is that we repalce the name field with '(parent)', and that we can
    # assume that it won't be an anonymous union.
    # Since most of the code is so similar, this should later be refactored.
    @staticmethod
    def parent(parent, depth, offset):
        if offset:
            offsetAttr = parent.attributes.get('DW_AT_data_member_location')
            if offset is not None and offsetAttr is not None:
                offset += offsetAttr.value
            else:
                offset = None

        if parent.attributes.get('DW_AT_type'):
            typeRef = parent.attributes.get('DW_AT_type').value
            parentType = die_list[parent.cu.cu_offset + typeRef]
            typeName, modifiers = getTypeAndModifiers(parentType)
        else:
            typeName = None
            modifiers = None

        return MemberInformation(
            '(parent)',
            typeName,
            depth,
            offset,
            modifiers)


class DIEInformation(dict):
    def __init__(self, die):
        name = getFullTypeName(die)
        if name is None:
            # If a type is unnamed, we don't really want to have anything to do it, as it's likely a
            # modifier type (e.g, DW_TAG_pointer_type, DW_TAG_const_type, etc.)
            return

        tag = die.tag

        size = None
        if die.attributes.get('DW_AT_byte_size'):
            size = die.attributes.get('DW_AT_byte_size').value

        subtype = None
        if die.attributes.get('DW_AT_type'):
            typeRef = die.attributes.get('DW_AT_type').value
            subtypeDie = die_list[die.cu.cu_offset + typeRef]
            subtype = getFullTypeName(subtypeDie)
        if not subtype:
            subtype = "(cannot find the type)"

        members = getMembers(die)

        vtable = getVtable(die)

        dict.__init__(self, 
            name=name,
            tag=tag,
            size=size,
            subtype=subtype,
            members=members,
            vtable=vtable)

# Given a type DIE, get the full name of that type, e.g, mongo::Value
def getFullTypeName(die):
    if die.attributes.get('DW_AT_name'):
        name = die.attributes.get('DW_AT_name').value
        parent = die.get_parent()
        while parent and parent.tag != 'DW_TAG_compile_unit':
            if parent.attributes.get('DW_AT_name'):
                name = parent.attributes.get('DW_AT_name').value + '::' + name
            parent = parent.get_parent()
        return name
    else:
        return None

# Given a type DIE, returns the name of the highest-level named type, along with any modifiers 
# (e.g, "const *") or None if there aren't any, returned as a 2-tuple.
def getTypeAndModifiers(die):
    global die_list
    if die.attributes.get('DW_AT_name'):
        return (getFullTypeName(die), None,)
    elif die.attributes.get('DW_AT_type') and die.tag in tag_modifier_map:
        typeRef = die.attributes.get('DW_AT_type').value
        typeDie = die_list[die.cu.cu_offset + typeRef]
        typeName, modifiers = getTypeAndModifiers(typeDie)
        return (typeName, modifiers + ' ' + tag_modifier_map[die.tag] 
            if modifiers is not None else 
            tag_modifier_map[die.tag])
    else:
        modifier = tag_modifier_map[die.tag] if die.tag in tag_modifier_map else None
        # The assumption made here is that if a type is unnamed, then it's void. I don't know if
        # this is true.
        return ("void", modifier)


# Given a type die, get a list of MemberInformation dicts for the members of that type
def getMembers(typeDie, depth=0, offset=0):
    global die_list
    members = []
    for child in typeDie.iter_children():
        if child.tag == 'DW_TAG_member':
            memberInfo = MemberInformation.member(child, depth, offset)
        elif child.tag == 'DW_TAG_inheritance':
            memberInfo = MemberInformation.parent(child, depth, offset)
        elif child.tag =='DW_TAG_typedef':
            # TODO: Handle typedefs as members
            continue
        else:
            continue

        if memberInfo is None:
            continue
        members.append(memberInfo)

        if memberInfo['offset'] is not None:
            _offset = memberInfo['offset']
        else:
            _offset = None
        if child.attributes.get('DW_AT_type'):
            typeRef = child.attributes.get('DW_AT_type').value
            typeDie = die_list[child.cu.cu_offset + typeRef]
            members += getMembers(typeDie, depth+1, _offset)
    return members

def isType(die, typeName):
    if not die.attributes.get('DW_AT_type'):
        return False
    typeRef = die.attributes.get('DW_AT_type').value
    typeDie = die_list[die.cu.cu_offset + typeRef]
    if typeDie.tag == typeName:
        return True
    return False

def getVtable(typeDie):
    global die_list
    vtable = {}
    for child in typeDie.iter_children():
        # Get the vtable entries from the parents
        if child.tag == 'DW_TAG_inheritance':
            parentRef = child.attributes.get('DW_AT_type').value
            parentDie = die_list[child.cu.cu_offset + parentRef]
            parentVtable = getVtable(parentDie)
            vtable = dict(vtable.items() + parentVtable.items())
    for child in typeDie.iter_children():
        if child.tag == 'DW_TAG_subprogram' \
        and child.attributes.get('DW_AT_virtuality') \
        and child.attributes.get('DW_AT_vtable_elem_location'):
            elem_location = child.attributes.get('DW_AT_vtable_elem_location')
            if elem_location.form == 'DW_FORM_exprloc':
                loc_pieces = describe_DWARF_expr(elem_location.value, child.cu.structs)
                # Not 100% sure what loc_pieces represents right now...
                index = loc_pieces[0]
                if child.attributes.get('DW_AT_linkage_name'):
                    name = child.attributes.get('DW_AT_linkage_name').value
                elif child.attributes.get('DW_AT_name'):
                    name = child.attributes.get('DW_AT_name').value
                else:
                    name = "(Cannot determine name)"
                vtable[index] = name
            elif elem_location.form == 'DW_FORM_loclistptr':
                print 'Cannot currently handle form DW_FORM_loclistptr'
            else:
                print 'Unexpected form {} for vtable_elem_location'.format(elem_location.form)
    return vtable