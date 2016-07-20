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

from capstone import x86
from bs4 import BeautifulSoup
soup = BeautifulSoup(open('static/inst_ref/index.html'), 'lxml')

# Maps an instruction mnemonic to its short description
description_map = None

def get_short_desc(instr):
    desc_map = get_description_map()
    mnemonic = instr.mnemonic.lower()
    if mnemonic in desc_map:
        return desc_map[mnemonic]
    # Jump instructions have a special page of documentation
    elif instr.group(x86.X86_GRP_JUMP):
        return desc_map['jcc']
    # Conditional move instructions have a special page of documentation
    elif instr.group(x86.X86_GRP_CMOV):
        return desc_map['cmovcc']
    # Instructions that start with 'v' may be vex-encoded, and so the 'v' should be stripped out
    elif instr.mnemonic[0] == 'v':
        return desc_map[mnemonic[1:]]
    else:
        return None
    return None

# Returns description_map, instantiating it if necessary
# description_map is a mapping of instruction mnemonics to their short descriptions
# Short descriptions are obtained by parsing index.html
def get_description_map():
    global description_map
    if description_map is None:
        description_map = {}
        # Sample table row in index.html
        # <tr>
        # <td><a href="./RCL:RCR:ROL:ROR.html">RCL</a></td>
        # <td>-Rotate</td></tr>
        # The short description relative to an "a" element is at the following location:
        # The link's parent's next sibling's next sibling's innerHTML
        # AKA: link.parent.next_sibling.next_sibling.string
        # NOTE: In actuality, the description is only one sibling over. But BeautifulSoup returns ""
        # for the following sibling. The correct results are at .next_sibling.next_sibling
        for link in soup.find_all('a'):
            innerHTML = link.string.lower()
            description_map[innerHTML] = link.parent.next_sibling.next_sibling.string
    return description_map