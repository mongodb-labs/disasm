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


/* INIT */
var URL_DISASM_FUNCTION = "/disasm_function";

// structure of each func in function.contents:
// {
//  name: [{
//    value: "",
//    display: "",
//    expandable: true/false
//    collapsable: int
//  }, ... ], 
//  offset: "", size: "", sh_addr: ""
// }
var functions = {
  contents: [], 
  functionsLoading: false,
  filename: document.getElementById('functions').getAttribute('data-filename')
};

var functions_ctrl = {
  functionClicked: functionClicked,
  hoverCollapsable: hoverCollapsable,
  removeHoverCollapsable: removeHoverCollapsable
};

rivets.bind($("#functions, .functions-loading-icon"), 
  { 
    functions: functions, 
    ctrl: functions_ctrl 
  }
);

rivets.formatters.function_href = function(func) {
  func_name = ''
  func.name.forEach(function(name_obj) {
    func_name += name_obj.display
  });

  request_params = {
    filename: functions.filename,
    st_value: func.st_value,
    file_offset: func.offset,
    func_name: func_name,
    size: func.size
  };

  return URL_DISASM_FUNCTION + '?' + $.param(request_params);
}

var curr_index = 0;
var NUM_FUNCTIONS = 100;

var selectedFunction = null;
/* END INIT */

// handle expansion/collapse of <> in function name
function functionClicked(event, model) {
  var el = event.currentTarget;
  if (event.target.classList.contains("expandable")) {
    event.preventDefault();
    expandFunctionName(event, model);
    return;
  }
  else if (event.target.classList.contains("collapsable")) {
    event.preventDefault();
    collapseFunctionName(event, model);
    return;
  }
}

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

// The current request
var searchRequest;
// Number of miliseconds to wait before checking to see if the request is stale
var SEARCH_DELAY = 10;
// Last successfully completed request
var prevRequest = "";

// helper for getting functions/pagination of functions
var functionsRequest;
function getNextPage(query, curr_index, num_functions) {
    searchRequest = query;
    setTimeout(function(){
        if (searchRequest !== query) {
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

        functions.functionsLoading = true;
        // cancel any outstanding requests so that we only 
        // deal with the latest one
        if (functionsRequest) {
          functionsRequest.abort();
        }
        functionsRequest = $.get('/get_substring_matches', { 
            filename: functions.filename,
            substring: query, 
            start_index: curr_index, 
            num_functions: num_functions, 
            case_sensitive: case_sensitive 
        })
        .done(function(funcs) {
        	// remove highlighted function
      		$(".selected").removeClass("selected");
            functions.contents = format_functions(funcs);
            var firstFunc = $(".function")[0];
            $(firstFunc).addClass('selected')
            selectedFunction = firstFunc;

            prevRequest = query;
            functions.functionsLoading = false;
        })
        .always(function() {
            console.log("Request complete.");
        });
    }, 100);
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
