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

from itertools import combinations
import re
from sets import Set
import sys
import heapq
import pickle
import cProfile
from datetime import datetime
import sys

subStringIndex = {}
functionsList = None

start = None

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

class FunctionMatch():
    def __init__(self, name, score):
        self.name = name
        self.score = score

    # By inverting the definition of "less than", we convert the min heap into a max heap
    def __lt__(self, other):
        return self.score > other.score

def getFunctionsBySubstring(substring, start_index, num_functions, case_sensitive):
    functions = []
    # ALGO = "RE"
    # if ALGO == "CMDT":
    #     for function in functionsList:
    #         # print "Scanning haystack '", function['name'], "'"
    #         haystack = filterName(function['name'])
    #         # print "Scanning haystack '", haystack, "'"
    #         memo = [None]*(len(substring) * len(function['name']))
    #         rightmost_match = get_rightmost_match(substring, haystack, case_sensitive)
    #         if rightmost_match is None:
    #             continue
    #         score = match(substring, 0, function["name"], 0, 0, 0.0, True, memo, rightmost_match)
    #         heapq.heappush(functions, FunctionMatch(function['name'], score))
    # elif ALGO == "RE":
    prog = re.compile(substring)
    for function in functionsList:
        # haystack = filterName(function['name'])
        haystack = function['name']
        if prog.search(haystack):
            functions.append(function)
            if len(functions) == start_index + num_functions:
                break
    # elif ALGO == "OG":
    #     if subStringIndex.has_key(substring):
    #         return subStringIndex[substring][start_index:start_index+num_functions]
    #     else:
    #         # pattern = ".*"
    #         # for char in substring:
    #         #     pattern += char + ".*"
    #         # # Check every function name to see if it matches the requested pattern
    #         # prog = re.compile(pattern, flags=re.IGNORECASE)
    #         if subStringIndex.has_key(substring[:-1]):
    #             listToIter = subStringIndex[substring[:-1]]
    #         else:
    #             listToIter = functionsList
    #         for function in listToIter:
    #             # if prog.match(function['name']):
    #             if matchesSubstring(function['name'], substring, case_sensitive):
    #                 functions.append(function)
    #         subStringIndex[substring] = functions
    # else:
    #     raise "Not a valid search algo"
    # print len(functions)
    return functions[start_index:start_index+num_functions]

def filterName(funcHeader):
    depth = 0
    string = []
    for char in funcHeader:
        if char == '>' or char == ')':
            depth -= 1
        if depth == 0:
            string.append(char)
        if char == '<' or char == '(':
            depth += 1
    return ''.join(string)

def get_rightmost_match(needle, haystack, case_sensitive):
    rightmost_match = [None]*len(needle)
    needle_index = len(needle)-1
    for i in range(len(haystack)-1, -1, -1):
        # if i == 38 and needle in haystack:
        #     import pdb; pdb.set_trace()
        c = haystack[i]
        if (c >= 'A' and c <= 'Z') and not case_sensitive:
            c = c.lower()
        if needle_index >= 0:
            d = needle[needle_index]
            if c == d:
                rightmost_match[needle_index] = i
                needle_index -= 1
    # if needle in haystack:
    #     import pdb; pdb.set_trace()
    if needle_index != -1:
        return None
    else:
        return rightmost_match

def matchesSubstring(string, substring, case_sensitive):
    if not case_sensitive:
        string = string.lower()
        substring = substring.lower()
    if len(substring) == 0:
        return True
    index = 0
    for char in string:
        if char == substring[index]:
            index += 1
        if index == len(substring):
            return True
    return False

# @profile
def match(needle, needle_start, haystack, haystack_start, last_index, score, case_sensitive, memo, rightmost_match):
    # if needle in haystack:
    #     import pdb; pdb.set_trace()
    seen_score = 0
    for i in range(needle_start, len(needle)):
        for j in range(haystack_start, rightmost_match[i]+1):
            global start
            diff = datetime.now() - start
            if diff.total_seconds() > 15:
                return
            memo_score = memo[j*len(needle)]
            if memo_score:
                # import pdb; pdb.set_trace()
                return max(memo_score, seen_score)
            c = needle[i]
            d = haystack[j]
            if (d >= 'A' and d <= 'Z') and not case_sensitive:
                d = d.lower()
            if c == d:
                max_char_score = (1.0 / len(haystack) + 1.0 / len(needle)) / 2
                char_score = calc_char_score(haystack, j, last_index, max_char_score)
                if (j < rightmost_match[i]):
                    sub_score = match(needle, i, haystack, j+1, last_index, score, case_sensitive, memo, rightmost_match)
                    if (sub_score > seen_score):
                        seen_score = sub_score
                last_index = j
                haystack_start = j + 1
                score += char_score
                # memo[j*len(needle)+i] = max(seen_score,score)
                memo[j*len(needle)+i] = max(seen_score,score)
                if i == len(needle) - 1:
                    # import pdb; pdb.set_trace()
                    return memo[j*len(needle)+i]
    # memo[len(haystack)*len(needle)+len(needle)] = score
    # return memo[j*len(needle)+i]
    # import pdb; pdb.set_trace()
    return score

# @profile
def calc_char_score(haystack, haystack_index, last_index, max_char_score):
    return 0
    # distance = haystack_index - last_index
    # if distance > 1:
    #     prev = haystack[haystack_index-1]
    #     curr = haystack[haystack_index]
    #     if prev == '/':
    #         factor = .9
    #     elif prev == '-' or prev == '_' or prev == ' ' or (prev >= '0' and prev <= '9'):
    #         factor = .8
    #     elif prev >= 'a' and prev <= 'z' and curr >= 'A' and curr <= 'Z':
    #         factor = .8
    #     elif prev == '.':
    #         factor = .7
    #     else:
    #         factor = (1.0/distance) * .75
    #     return max_char_score * factor
    # else:
    #     return max_char_score

def test(argv):
    global start
    start = datetime.now()
    with open('functions_list.txt', 'r') as f:
        global functionsList
        functionsList = pickle.load(f)
    # matches = getFunctionsBySubstring("vector.*push", 0, 20, False)
    matches = getFunctionsBySubstring("e", 100, 20, False)
    # for matchItem in matches:
    #     print "%f : %s" % (matchItem.score, matchItem.name)

    # functionsList = ["lolNiceMeme", "notInCatEars", "insdiascde"]    
    # needle = "nice"
    # for func in functionsList:
    #     rightmost_match = get_rightmost_match(needle, func, False)
    #     if rightmost_match is None:
    #         continue
    #     score = match(needle, 0, func, 0, 0, 0.0, False, [None]*(len(needle) * len(func)), rightmost_match)
    #     print "%f : %s" % (score, func)

if __name__ == '__main__':
    test(sys.argv[1:])