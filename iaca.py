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

import subprocess, sys, os
from cStringIO import StringIO

MARKER_START = bytearray(['\x0f', '\x0b', '\xbb', '\x6f', '\x00', '\x00', '\x00', '\x64', '\x67', '\x90'])
MARKER_END = bytearray(['\xbb', '\xde', '\x00', '\x00', '\x00', '\x64', '\x67', '\x90', '\x0f', '\x0b'])

# call the command line iaca tool; returns [name of file with output], [error]
def run(b, arch_type, analysis_type, iaca_path=None, dyld_lib_path=None):
	bytes_in = MARKER_START + b + MARKER_END
	temp_inputfile = 'temp.iaca.in'
	temp_outfile = 'temp.iaca.out'

	with open(temp_inputfile, 'w+') as f:
		f.write(bytes_in)
		f.seek(0)
		try:
			if iaca_path != None:
				os.environ["PATH"] += ':' + iaca_path
			if dyld_lib_path != None:
				os.environ["DYLD_LIBRARY_PATH"] = dyld_lib_path

			with open(temp_outfile, 'w') as outfile:
				subprocess.call(["iaca", '-64', '-arch', arch_type, '-analysis', analysis_type,
					'-graph', 'temp.iaca.graph', temp_inputfile], stdout=outfile)
		except Exception as e:
			return None, e
	
	os.remove(temp_inputfile)
	return temp_outfile, None
