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

from collections import namedtuple
from elftools.dwarf.die import DIE
from elftools.dwarf.ranges import RangeEntry
from elftools.dwarf.descriptions import describe_form_class
from bisect import bisect_right

ARangeEntry = namedtuple('ARangeEntry', 'begin_addr length info_offset')

class CURanges(object):
    def __init__(self, dwarfinfo):
        # get address ranges in each CU
        self.entries = self._get_entries(dwarfinfo)

        # Sort entries by the beginning address
        self.entries.sort(key=lambda entry: entry.begin_addr)

        # Create list of keys (first addresses) for better searching
        self.keys = [entry.begin_addr for entry in self.entries]

    def cu_offset_at_addr(self, addr):
        """ Given an address, get the offset of the CU it belongs to, where
            'offset' refers to the offset in the .debug_info section.
        """
        tup = self.entries[bisect_right(self.keys, addr) - 1]
        return tup.info_offset

    def _get_entries(self, dwarfinfo):
        entries = []
        for cu in dwarfinfo.iter_CUs():
            first_DIE = DIE(cu=cu, stream=dwarfinfo.debug_info_sec.stream, offset=cu.cu_die_offset)
            addr_ranges = self._get_DIE_addrs(dwarfinfo, first_DIE)
            if not addr_ranges:
                continue
            for range_entry in addr_ranges:
                entries.append(ARangeEntry(begin_addr=range_entry.begin_offset, 
                        length=range_entry.end_offset - range_entry.begin_offset,
                        info_offset=cu.cu_offset))
        return entries

    def _get_DIE_addrs(self, dwarfinfo, DIE):
        if "DW_AT_ranges" in DIE.attributes:
            offset = DIE.attributes["DW_AT_ranges"].value
            range_lists = dwarfinfo.range_lists()
            ranges = range_lists.get_range_list_at_offset(offset)
            # RangeEntry = (begin_offset, end_offset)
            return ranges
        elif "DW_AT_low_pc" in DIE.attributes and "DW_AT_high_pc" in DIE.attributes:
            lo = int(DIE.attributes["DW_AT_low_pc"].value)
            high_pc = DIE.attributes["DW_AT_high_pc"]
            highpc_attr_class = describe_form_class(high_pc.form)
            if highpc_attr_class == 'address':
                hi = int(high_pc.value)
            elif highpc_attr_class == 'constant':
                hi = lo + int(high_pc.value)       
            else:
                print('Error: invalid DW_AT_high_pc class:', highpc_attr_class)
            return [RangeEntry(begin_offset=lo, end_offset=hi)]
        elif "DW_AT_low_pc" in DIE.attributes:
            print "only has low_pc...."
            lo = int(DIE.attributes["DW_AT_low_pc"].value)
            return [RangeEntry(begin_offset=lo, end_offset=lo)]
        else:
            return None
