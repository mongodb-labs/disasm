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
from collections import namedtuple
from os import listdir
from os.path import isfile, join, dirname
from bs4 import BeautifulSoup

INST_REF_PATH = join(dirname(__file__), 'static/inst_ref/')
soup = BeautifulSoup(open(INST_REF_PATH + '/index.html'), 'lxml')

# Maps an instruction mnemonic to a namedtuple (short_desc, doc_file)
# DO NOT ACCESS DIRECTLY. Instead us the get_documentation_map() function
documentation_map = None

# instr : <class 'capstone.CsInsn'>
#   Instruction for which documentation is requested
#
# Returns: <named-2-tuple>:
#   (short_desc, doc_file,)
#   short_desc : <str>
#       Short description of the instruction, obtained from index.html
#   doc_file : <str>
#       Name of the file for which full documentation an be obtained
def get_documentation(instr):
    # First use the instruction object to check if the group indicates which documentation to use.
    doc = check_group(instr)
    if not doc == (None, None):
        return doc

    # Split to ignore prefixes, then lower to ignore prefixes
    mnemonic = instr.mnemonic.split()[-1].lower()
    # Use the mnemonic itself to determine which documentation to use.
    doc = check_mnemonic(mnemonic)
    if not doc == (None, None):
        return doc

    return (None, None)

def check_group(instr):
    doc_map = get_documentation_map()

    # All jump instructions EXCEPT for jmp have a special page of documentation
    if instr.group(x86.X86_GRP_JUMP) and instr.mnemonic != 'jmp':
        return doc_map['jcc']
    if instr.group(x86.X86_GRP_CMOV):
        return doc_map['cmovcc']
    return (None, None)

def check_mnemonic(mnemonic):
    doc_map = get_documentation_map()

    if mnemonic in doc_map:
        return doc_map[mnemonic]
    # Conditional set instructions have a special page of documentation
    elif mnemonic.startswith('set'):
        return doc_map['setcc']
    # Conditional loop instructions have a special page of documentation
    elif mnemonic.startswith('loop'):
        return doc_map['loopcc']
    # Conditional fcmov instructions have a special page of documentation
    elif mnemonic.startswith('fcmov'):
        return doc_map['fcmovcc']
    # movabs is a special encoding of mov
    elif mnemonic.startswith('movabs'):
        return doc_map['mov']
    # PREFETCH0, PREFETCH1, PREFETCH2, PREFETCHNTA
    elif mnemonic.startswith('prefetch'):
        return doc_map['prefetchh']
    # vbroadcast.*
    elif mnemonic.startswith('vbroadcast'):
        return doc_map['vbroadcast']
    # "cmp.*sd"
    elif mnemonic.startswith('cmp') and mnemonic.endswith('sd'):
        return doc_map['cmpsd']
    # fucompi maps to fucomip
    elif mnemonic == 'fucompi':
        return doc_map['fucomip']
    # If none of the above instructions apply, then we may need to change certain pieces and try
    # again.
    else:
        if mnemonic.startswith('v'):
            doc = check_mnemonic(mnemonic[1:])
            if not doc == (None, None):
                return doc
        if mnemonic.endswith('ss'):
            doc = check_mnemonic(mnemonic.replace('ss', 'sd'))
            if not doc == (None, None):
                return doc
    return (None, None)

    # # Instructions that start with 'v' may be vex-encoded, and so the 'v' should be stripped out
    # # then tested again
    # elif instr.mnemonic.startswith('v') and mnemonic[1:] in doc_map:
    #     # Here I save the instruction mnemonic, change instr.mnemonic to remove the leading 'v', run 
    #     # the function again, then move the original mnemonic back so that no permanent damage is 
    #     # done.
    #     # I haven't figured out a cleaner way to do this but if you figure one out, let me know.
    #     _tmp_mnemonic = instr.mnemonic
    #     instr.mnemonic = mnemonic[1:]
    #     doc = get_documentation(instr)
    #     instr.mnemonic = _tmp_mnemonic
    #     return doc
    # elif instr.mnemonic.endswith('ss')
    # else:
    #     return (None, None)

def get_documentation_map():
    global documentation_map
    if documentation_map is None:
        documentation_map = {}
        set_short_descriptions()
        set_doc_files()
    return documentation_map

def set_short_descriptions():
    global documentation_map
    for link in soup.find_all('a'):
        innerHTML = link.string.lower().strip()
        entry = documentation_map.get(
            innerHTML, 
            namedtuple('DocumentationEntry', ['short_desc', 'doc_file'])(None, None))
        entry = entry._replace(short_desc=link.parent.next_sibling.next_sibling.string)
        documentation_map[innerHTML] = entry

def set_doc_files():
    global documentation_map
    # http://stackoverflow.com/questions/3207219/how-to-list-all-files-of-a-directory-in-python
    filelist = [f for f in listdir(INST_REF_PATH) if isfile(join(INST_REF_PATH, f))]
    for f in filelist:
        mnemonics = f[:-5].lower().split(':')
        for mnemonic in mnemonics:
            mnemonic = mnemonic.strip()
            entry = documentation_map.get(
                mnemonic,
                namedtuple('DocumentationEntry', ['short_desc', 'doc_file'])(None, None))
            entry = entry._replace(doc_file=f)
            documentation_map[mnemonic] = entry