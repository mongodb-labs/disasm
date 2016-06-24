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

var functions = {contents: []}
rivets.bind($("#functions"), {functions: functions});

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
            functions.contents = funcs;
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


rivets.formatters.collapse_func = function(name) {
	str = chunk_str(name);
	res = "";
	for (var i = 0; i < str.length; i++) {
		if (i%2 == 0) {
			res += str[i];
		}
		else {
			res += "<span class='expandable'><...></span>";
		}
	}
	return res;
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
			console.log("this should never happen");
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

