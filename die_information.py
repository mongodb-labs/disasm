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

class MemberInformation(dict):
    def __init__(self, name, type, offset):
        return dict.__init__(self,
            name=name,
            type=type,
            offset=offset,
            depth=None)

    @staticmethod
    def member(child, offset):
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
        if offsetAttr and offset is not None:
            offset += offsetAttr.value 
        elif child.attributes.get('DW_AT_external'):
            # Later on, we may want to handle this so that we can explicitly show the user that this
            # member is externally defined.
            offset = None
        else:
            offset = None
        
        return MemberInformation(name, typeName, offset)

    @staticmethod
    def parent(parent_die, offset):
        if offset:
            offsetAttr = parent_die.attributes.get('DW_AT_data_member_location')
            offset = offset.value if offsetAttr else None
        return MemberInformation(
            '(parent)',
            getSubtype(parent_die),
            offset)


class DIEInformation(dict):
    def __init__(self, die):
        # If a type is unnamed, then it's likely a pointer, const, ref, etc. We really only care
        # about the type that it actually identifies, which will later be identified. As such, we
        # can reasonably skip unnamed types, as we don't care about pointers, references, etc.
        if not die.attributes.get('DW_AT_name'):
            return

        name = die.attributes.get('DW_AT_name').value
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
            tag=tag,
            size=size,
            name=name,
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
def getMembers(die, offset=0):
    members = []
    for child in die.iter_children():
        memberInfo = None
        if child.tag == 'DW_TAG_member':
            memberInfo = MemberInformation.member(child, offset)
        elif child.tag == 'DW_TAG_inheritance':
            memberInfo = MemberInformation.parent(child, offset)
        else:
            continue
        if memberInfo:
            members.append(memberInfo)
    return members