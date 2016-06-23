var curr_index = 0;
var NUM_FUNCTIONS = 100;

var functions = {contents: []}
rivets.bind($("#functions"), {functions: functions});

var searchbar = $('#function-name-input');

// helper for getting functions/pagination of functions
function getNextPage(query, curr_index, num_functions) {
  $.get('/get_substring_matches', { substring: query, start_index: curr_index, num_functions:num_functions } )
    .done(function(funcs) {
      functions.contents = funcs;
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

