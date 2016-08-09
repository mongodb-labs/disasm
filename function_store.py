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

functionsList = {}

start = None

def storeFunctions(filename, functions):
    # Store the list of functions in a global list.
    global functionsList
    functionsList[filename] = functions

def hasStoredFunctions(filename):
    global functionsList
    return functionsList.get(filename) is not None

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

def getFunctionsBySubstring(filename, substring, start_index, num_functions, case_sensitive):
    functions = []
    try:
        if case_sensitive:
            prog = re.compile(substring)
        else:
            prog = re.compile(substring, re.IGNORECASE)
        for function in functionsList[filename]:
            haystack = function['name']
            if prog.search(haystack):
                functions.append(function)
                if len(functions) == start_index + num_functions:
                    break
        return functions[start_index:start_index+num_functions]
    except:
        return []

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
                memo[j*len(needle)+i] = max(seen_score,score)
                if i == len(needle) - 1:
                    return memo[j*len(needle)+i]
    return score
