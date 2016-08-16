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

# Maps of each DIE offset to the corresponding DIE.
# Used when trying to follow DIE type references, i.e., a DW_TAG_typedef DIE that has a DW_AT_type
# attribute that refers to a DW_TAG_base_type DIE.
die_list = {}

# Clears the die then maps each DIE offset to the corresponding DIE.
def reset_die_list(cu):
    global die_list
    # Would it be better to do die_list.clear()?
    die_list = {}
    for die in cu.iter_DIEs():
        die_list[die.offset] = die

class MemberInformation(dict):
    def __init__(self, name, type, depth, offset):
        return dict.__init__(self,
            name=name,
            type=type,
            depth=depth,
            offset=offset)

    @staticmethod
    def member(child, depth, offset):
        name = None
        typeName = None

        if child.attributes.get('DW_AT_name'):
            name = child.attributes.get('DW_AT_name').value
        else:
            name = "Cannot find the name of this member"

        # member type
        childType = getSubtype(child)
        if childType:
            typeName = childType
        else:
            typeName = None

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
            offset)

    @staticmethod
    def parent(parent_die, depth, offset):
        if offset:
            offsetAttr = parent_die.attributes.get('DW_AT_data_member_location')
            offset = offsetAttr.value if offsetAttr else None
        return MemberInformation(
            '(parent)',
            getSubtype(parent_die),
            depth,
            offset)


class DIEInformation(dict):
    def __init__(self, die):
        # If a type is an unnamed union, we can handle that as a separate special case
        if die.attributes.get('DW_AT_name'):
            name = die.attributes.get('DW_AT_name').value
        elif die.tag == 'DW_TAG_union_type':
            name = "(anonymous union)"
        else:
            return None

        tag = die.tag

        size = None
        if die.attributes.get('DW_AT_byte_size'):
            size = die.attributes.get('DW_AT_byte_size').value

        subtype = None
        if die.attributes.get('DW_AT_type'):
            subtype = getSubtype(die)
        else:
            subtype = "Cannot find the type"

        members = getMembers(die)

        dict.__init__(self, 
            name=name,
            tag=tag,
            size=size,
            subtype=subtype,
            members=members)

# Some types are actually defined as a more detailed variant on another type. For example, an int*
# is a pointer type with an int subtype so-to-speak. This example represented in DWARF as 
# DW_TAG_pointer_type with a DW_AT_type attribute that points to DW_TAG_base_type with a
# DW_AT_name attribute of "int". 
# If a type defines the DW_AT_type attribute, I call that the subtype.
# This concept was removed. Say you have a Foo struct. One of its members is of type Foo*. The
# subtype of this member will show up as Foo. This would cause infinite recursion in 
# executable._getMembers. Instead, this currently only returns the top-level type name, or None if
# there is no top-level type or if the type does not have a name.
def getSubtype(die):
    subtype = die.attributes.get('DW_AT_type')
    if subtype:
        subtypeRef = subtype.value
    else:
        return None
    die = DIE(die.cu, die.stream, die.cu.cu_offset + subtypeRef)
    if die.attributes.get('DW_AT_name'):
        return die.attributes.get('DW_AT_name').value
    else:
        return None

# Given a type die, get a list of MemberInformation dicts for the members of that type
def getMembers(typeDie, depth=0, offset=0):
    global die_list
    members = []
    for child in typeDie.iter_children():
        if child.tag == 'DW_TAG_member':
            memberInfo = MemberInformation.member(child, depth, offset)
        elif child.tag == 'DW_TAG_inheritance':
            memberInfo = MemberInformation.parent(child, depth, offset)
        else:
            continue

        if memberInfo is None:
            continue
        members.append(memberInfo)

        if memberInfo['offset'] is not None and offset is not None:
            _offset = memberInfo['offset'] + offset
        else:
            _offset = None
        if child.attributes.get('DW_AT_type'):
            typeRef = child.attributes.get('DW_AT_type').value
            typeDie = die_list[child.cu.cu_offset + typeRef]
            members += getMembers(typeDie, depth+1, _offset)
    return members