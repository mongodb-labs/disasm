from itertools import combinations
import re
from sets import Set
import sys

subStringIndex = {}
functionsList = None

def storeFunctions(functions):
    # Store the list of functions in a global list.
    #import pdb; pdb.set_trace()
    global functionsList
    functionsList = functions

def getFunctions(start_index, num_functions):
    global functionsList
    if functionsList:
        return functionsList[start_index:start_index+num_functions]
    else:
        return None

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

# Given a string of the form AB...MN, generate a regex pattern of the form .*A.*B ... .*M.*N.*
def getFunctionsBySubstring(substring, start_index, num_functions):
    if subStringIndex.has_key(substring):
        return subStringIndex[substring][start_index:start_index+num_functions]
    else:
        functions = []
        # pattern = ".*"
        # for char in substring:
        #     pattern += char + ".*"
        # # Check every function name to see if it matches the requested pattern
        # prog = re.compile(pattern, flags=re.IGNORECASE)
        if subStringIndex.has_key(substring[:-1]):
            listToIter = subStringIndex[substring[:-1]]
        else:
            listToIter = functionsList
        for function in listToIter:
            # if prog.match(function['name']):
            if matchesSubstring(function['name'], substring):
                functions.append(function)
        subStringIndex[substring] = functions
        return functions[start_index:start_index+num_functions]

def matchesSubstring(string, substring):
    if len(substring) == 0:
        return True
    index = 0
    for char in string:
        if char == substring[index]:
            index += 1
        if index == len(substring):
            return True
    return False

def test(argv):
    print argv[0]
    print argv[1]
    print matchesSubstring(argv[0], argv[1])

if __name__ == '__main__':
    test(sys.argv[1:])