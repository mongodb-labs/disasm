from itertools import combinations
import re
from sets import Set

subStringIndex = {}
functionsList = []

def storeFunctionNames(functions):
    # Store the list of functions in a global list.
    functionsList = functions

# This takes far too long, and there's not enough RAM in the room to complete this operation.
def indexSubstrings(functions):
    for index, funcName in enumerate(functions):
        for length in range(1, len(funcName)+1):
            subStrings = set(combinations(funcName, length))
            for subString in subStrings:
                subString = ''.join(subString)
                if subStringIndex.has_key(subString):
                    subStringIndex[subString].append(index)
                else:
                    subStringIndex[subString] = [index]
    print subStringIndex

def getFunctionsBySubstring(substring):
    # Given a string of the form AB...MN, generate a regex pattern of the form .*A.*B ... .*M.*N.*
    strings = []
    pattern = ".*"
    for char in substring:
        pattern += char + ".*"
    # Check every function name to see if it matches the requested pattern
    prog = re.compile(pattern, flags=re.IGNORECASE)
    for function in functionsList:
        if prog.match(function.name):
            strings.append(string)
    return strings