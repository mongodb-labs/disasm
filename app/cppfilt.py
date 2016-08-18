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

# If we can import from demangler, then do so.
# Otherwise, use the version of demangle we have

import sys, os
from subprocess import Popen, PIPE

def get_cppfilt_process():
    try:
        return Popen(["gc++filt"], stdin=PIPE, stdout=PIPE, stderr=sys.stdout)
    except OSError as e:
        if e.errno == os.errno.ENOENT:
            # try c++filt
            try:
                return Popen(["c++filt"], stdin=PIPE, stdout=PIPE, stderr=sys.stdout)
            except:
                return None
        else:
            return None

process = get_cppfilt_process()
if not process:
    raise OSError("You don't seem to have gc++filt or c++filt on your machine. "
        "You must have one of the two to use pypy")

def demangle(mangled):
    process.stdin.write(mangled + "\n")
    process.stdin.flush()
    demangled = process.stdout.readline()
    # strip the newline that is returned
    return demangled[:-2] 

