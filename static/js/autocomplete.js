/* 
 * Copyright 2016 MongoDB Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

var curr_index = 0;
var NUM_FUNCTIONS = 100;

// structure of each func in function.contents:
// {
//	name: [{
//   	value: "",
// 		display: "",
//   	expandable: true/false
//		collapsable: int
//  }, ... ], 
//  offset: "", size: "", sh_addr: ""
// }
var functions = {contents: []};
var functions_ctrl = {
	functionClicked: functionClicked, // located in disassemble.js
	hoverCollapsable: hoverCollapsable,
	removeHoverCollapsable: removeHoverCollapsable
};

rivets.bind($("#functions"), 
	{ 
		functions: functions, 
		ctrl: functions_ctrl 
	}
);


function format_function_name(str_name) {
	var parts = chunk_str(str_name);
	var name = []
	// build name array
	for (var i = 0; i < parts.length; i++) {
		var part = {}
		part.value = parts[i];
		part.expandable = (i%2 == 1);
		if (part.expandable) {
			part.display = "<...>";
		}
		else {
			part.display = part.value;
		}
		name.push(part);
	}
	return name;
}

function format_functions(functions) {
	var updated = functions.map(function(func) {
		func.name = format_function_name(func.name);
		return func;
	});
	return updated;
}

// return outer section, inner section, outersection, [inner section, outersection ...]
// inner sections will include outermost brackets
function chunk_str(str) {
	var STATE = "outer";
	var parts = [];
	var last_index = 0;
	var lb_count = 0;

	for (var i = 0; i < str.length; i++) {
		var c = str.charAt(i);
		if (c == '<' && STATE == "outer") {
			parts.push(str.slice(last_index, i));
			last_index = i;
			lb_count++;
			STATE = "inner";
		}
		else if (c == '<' && STATE == "inner") {
			lb_count++;
		}
		else if (c == '>' && STATE == "outer") {
			// pass
		}
		else if (c == '>' && STATE == "inner") {
			lb_count--;
			// if we've exited the "inner" section
			if (lb_count == 0) {
				parts.push(str.slice(last_index, i+1));
				last_index = i+1;
				STATE = "outer";
			}
		}
		else {
			continue;
		}
	}

	// last outersection
	parts.push(str.slice(last_index));
	return parts;
}

var searchbar = $('#function-name-input');

var searchRequest;
// Number of miliseconds to wait before checking to see if the request is stale
var SEARCH_DELAY = 10;

// helper for getting functions/pagination of functions
function getNextPage(query, curr_index, num_functions) {
    searchRequest = query;
    setTimeout(function(){
        if (searchRequest !== query) {
            console.log("Discarding request: " + query);
            return;
        }
        searchRequest = "";
        var case_sensitive = false;
        // Test to see if the query has any capital letters. If it does, then the search must be
        // case sensitive
        // http://stackoverflow.com/questions/2830826/javascript-checking-for-any-lowercase-letters-in-a-string
        if (query.toLowerCase() !== query) {
            case_sensitive = true;
        }
        $.get('/get_substring_matches', { 
                substring: query, 
                start_index: curr_index, 
                num_functions: num_functions, 
                case_sensitive: case_sensitive 
        })
          .done(function(funcs) {
            functions.contents = format_functions(funcs);
        })
        .fail(function() {
            alert("Unable to contact server.");
        })
        .always(function() {
            console.log("Request complete.");
        });
    }, 10);
}

// search bar 
$('#function-name-input').on('keyup', function() {
  if (this.value.length >= 3) {
  	getNextPage(this.value, 0, NUM_FUNCTIONS);
  }
});

$('#button-prev').click(function() {
    curr_index -= NUM_FUNCTIONS;
    if (curr_index < 0) {
        curr_index = 0;
    }
    getNextPage(searchbar.val(), curr_index, NUM_FUNCTIONS);
});

$('#button-next').click(function() {
    curr_index += NUM_FUNCTIONS;
    getNextPage(searchbar.val(), curr_index, NUM_FUNCTIONS);
});

/*
	for function declaration highlighting
*/

// get the index of the part of the name that was clicked
// helper function because of rivet weirdness
function getTargetPartIndex(event) {
	var OFFSET = -2 // because of rivet weirdness
	var node = event.target
	var i = OFFSET;
	while((node = node.previousSibling) != null) {i++};
	return i;
}

function hoverCollapsable(event, model) {
	if (!event.target.classList.contains("collapsable")) {
		return;
	}

	var i = getTargetPartIndex(event);
	var func = functions.contents[model.index];
	var collapse_id = func.name[i].collapsable;

	for (var j = 0; j < func.name.length; j++) {
		if (func.name[j].collapsable == collapse_id) {
			func.name[j].hovered = true;
		}
	}
}

function removeHoverCollapsable(event, model) {
	if (!event.target.classList.contains("collapsable")) {
		return;
	}
	var func = functions.contents[model.index];
	for (var j = 0; j < func.name.length; j++) {
		func.name[j].hovered = false;
	}
}

// when you click a "<...>"
function expandFunctionName(event, el) {
	var i = getTargetPartIndex(event);
	
	// which part of the function name is collapsed?
	var func = functions.contents[el.index];
	var part = func.name[i];
	var newParts = format_function_name(part.value.slice(1, -1));

	// display brackets correctly & update the collapsable part
	for (var j = 0; j < newParts.length; j++) {
		if (j == 0) {
			newParts[0].value = "<" + newParts[0].value;
			newParts[0].display = newParts[0].value;
		}
		if (j == newParts.length - 1) {
			newParts[j].value = newParts[j].value + ">";
			newParts[j].display = newParts[j].value;
		}
		if (j % 2 == 0) {
			newParts[j].collapsable = i;
			newParts[j].expandable = false;
		}
		else {
			newParts[j].collapsable = undefined;
			newParts[j].expandable = true;
		}
	}

	// renders to DOM
	func.name = func.name.slice(0, i).concat(newParts, func.name.slice(i+1));
}

// when you click something collapsable
function collapseFunctionName(event, el) {
	var i = getTargetPartIndex(event);
	
	// which part of the function name was clicked?
	var func = functions.contents[el.index];	
	var part = func.name[i];
	var collapse_id = part.collapsable;

	// get the bookend parts with the collapse_id
	var first = undefined;
	var last = undefined;
	for (var j = 0; j < func.name.length; j++) {
		if (first == undefined && func.name[j].collapsable == collapse_id) {
			first = j;
		}
		if (func.name[j].collapsable == collapse_id) {
			last = j;
		}
	}
	
	// create new part
	var newPart = {
		value: "",
		display: "",
		expandable: true,
		collapsable: undefined
	}
	for (var j = first; j <= last; j++) {
		newPart.value += func.name[j].value;
	}
	newPart.display = "<...>";

	// splice into func.name
	func.name = func.name.slice(0, first).concat([newPart], func.name.slice(last+1));
}

/*

CMD+T

Terms:
- needle -- The string entered that you are trying to match
- haystack -- The string you are searching through
- score -- How highly the strings match. Higher scores are assigned for characters that appear at
    after a space, after a hyphen, after an underscore, after a period, and for uppercase characters
    that appear after a lowercase character (camelcase). Lower scores are assigned for characters
    that are further away from the last matched character
- memo -- 2D array. len(needle) x len(haystack). Stores the greatest score seen so far for a
    pairing btwn a character in needle and a character in haystack

Basic algo:
match(needle_start, needle_len, haystack_start, haystack_end, last_index, score):
    seen_score = 0
    for i = needle_start to needle_len:
        for j = haystack_start to haystack_end:
            c = needle[i]
            d = haystack[j]
            if case_sensitive:
                d = lower(d)
            if c == d:
                char_score = calculate_char_score()
                sub_score = match(j+1, needle_len, i, haystack_end, last_index, score):
                if (sub_score > seen_score):
                    seen_score = sub_score
                last_index = j
                haystack_start = j + 1
                score += char_score
                if i == needle_len - 1:
                    return seen_score > score ? seen_score : score
    return score

I think.... Maybe run through this on Monday to make sure it's right

*/