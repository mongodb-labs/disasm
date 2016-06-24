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
//	name: {
//   	value: "",
// 		display: "",
//   	expandable: true/false
//  }, 
//  offset: "", size: ""
// }
var functions = {contents: []};
var ctrl = {
	something: function(e, model) {
		console.log("ffs")
	},
	expand: function(e, model) {
		console.log(e);
		console.log(model);
		var p = model.part
		if (p.expandable && p.display != p.value) {
			p.display = p.value;
		}
		else if (p.expandable && p.display == p.value) {
			model.part.display = "<...>";
		}
	}
};

rivets.bind($("#functions"), 
	{ 
		functions: functions, 
		ctrl: ctrl 
	}
);


function format_functions(functions) {
	var updated = functions.map(function(func) {
		var parts = chunk_str(func.name);
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
		func.name = name;
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

var searchbar = $('#function-name-input');

// initialize with first functions
if (functions.contents.length == 0) {
	getNextPage("", 0, NUM_FUNCTIONS);
}

// helper for getting functions/pagination of functions
function getNextPage(query, curr_index, num_functions) {
  $.get('/get_substring_matches', { substring: query, start_index: curr_index, num_functions:num_functions } )
    .done(function(funcs) {
      functions.contents = format_functions(funcs);
    })
    .fail(function() {
      alert("Unable to contact server.");
    })
    .always(function() {
      console.log("Request complete.");
    });
}

// search bar 
$('#function-name-input').on('keyup', function() {
  if (this.value.length >= 1) {
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