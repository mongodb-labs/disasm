import sys, os, pickle
from app import metadata
sys.modules['metadata'] = metadata

data = {}
for filename in os.listdir('.metadata/'):
    filepath = os.path.join('.metadata/', filename)
    with open(filepath) as mdFile:
        data[filename] = pickle.load(mdFile)

del sys.modules['metadata']

for filename in os.listdir('.metadata/'):
    filepath = os.path.join('.metadata/', filename)
    with open(filepath, 'a') as mdFile:
        mdFile.seek(0)
        mdFile.truncate()
        pickle.dump(data[filename], mdFile)