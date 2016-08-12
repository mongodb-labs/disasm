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

        members = []
        if die.has_children:
            for child in die.iter_children():
                if child.tag == 'DW_TAG_member':
                    member = {'name': None, 'type': None, 'offset': None}

                    # member name
                    if child.attributes.get('DW_AT_name'):
                        member['name'] = child.attributes.get('DW_AT_name').value
                    else:
                        member['name'] = "Cannot find the name of this member"

                    # member type
                    childType = getSubtype(child)
                    if childType:
                        member['type'] = childType
                    else:
                        member['type'] = "Cannot find the type of this member"

                    # member offset
                    if child.attributes.get('DW_AT_data_member_location'):
                        member['offset'] = child.attributes.get('DW_AT_data_member_location').value
                    elif child.attributes.get('DW_AT_external'):
                        member['offset'] = "Static variable. No offset data available"
                    else:
                        member['offset'] = "Cannot find the offset of this member"

                    members.append(member)

                elif child.tag == 'DW_TAG_subprogram':
                    # member function
                    pass
                else:
                    # neither a member variable nor a member function
                    pass

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
def getSubtype(die):
    subtype = die
    while subtype.attributes.get('DW_AT_type'):
        subtypeRef = subtype.attributes.get('DW_AT_type').value
        subtype = DIE(subtype.cu, subtype.stream, subtype.cu.cu_offset + subtypeRef)
        if subtype.attributes.get('DW_AT_name'):
            return subtype.attributes.get('DW_AT_name').value