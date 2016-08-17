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

import hurry.filesize
import os
import datetime
import pickle
import uuid
import argparse
from sets import Set

METADATA = '.metadata'
PARENT_PATH = os.path.dirname(os.path.dirname(__file__))
METADATA_DIR = os.path.join(PARENT_PATH, METADATA)

class FileMetadata:
    def __init__(self, path, from_cmd=False):
        self.path = os.path.abspath(path)
        self.basename = os.path.basename(self.path)
        t = os.path.getmtime(self.path)
        self.timestamp = datetime.datetime.fromtimestamp(t)
        size = os.path.getsize(self.path)
        self.size = hurry.filesize.size(size)
        self.from_cmd = from_cmd
        self.UUID = str(uuid.uuid1())

    def __str__(self):
        return str(self.__dict__)

    def getTimeAndSize(self):
        return [self.timestamp, self.size]

    def save(self):
        if not os.path.exists(METADATA):
            os.makedirs(METADATA)
        with open(os.path.join(METADATA_DIR, self.UUID), 'a') as f:
            # We seek to the beginning on the offchance that someone is attempting to rewrite the
            # metadata file.
            f.seek(0)
            f.truncate()
            pickle.dump(self, f)

def fromFilePath(path):
    return FileMetadata(path)

def fromFileObject(fp):
    return FileMetadata(fp.name)

def fromCommandLine(path):
    return FileMetadata(path, True)

def getExistingMetadata():
    # If for some reason the metadata directory cannot be found, then create it and return []
    if not os.path.exists(METADATA_DIR):
        os.makedirs(METADATA_DIR)
        return []
    res = []
    parser = argparse.ArgumentParser()
    try:
        parser.add_argument('-f', '--files', dest='files', nargs='+')
        # Create a set of all of the absolute paths referenced in the commandline
        cmdFileSet = Set([os.path.abspath(path) for path in parser.parse_args().files])
    except:
        cmdFileSet = Set([])
        
    for f in os.listdir(METADATA_DIR):
        filepath = os.path.join(METADATA_DIR, f)
        if os.path.isfile(filepath):
            try:
                with open(filepath) as mdFile:
                    md = pickle.load(mdFile)
                    # If a metadata file exists for a file that was referenced on the command line, only
                    # add it to the list if that path is still being referenced on the command line now
                    if not md.from_cmd or md.path in cmdFileSet:
                        res.append(md)
            # We assume all files in this directory are valid FileMetadata objects. Some unwanted
            # files may end up in the directory. To keep it from panicking, just skip it
            except:
                pass

    return sorted(res, key=lambda x: x.timestamp, reverse=True)

def fromUUID(UUID):
    with open(os.path.join(METADATA_DIR, UUID)) as f:
        md = pickle.load(f)
        return fromFilePath(md.path)

# 1 for OK, 0 for error
def deleteFile(UUID):
    # currently not deleting the actual file in /uploads. should we be??
    try:
        os.remove(os.path.join(METADATA_DIR, UUID))
        return 1
    except:
        return 0




