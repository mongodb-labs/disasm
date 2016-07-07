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

var analysis = {
	stack_info: [],
	show_stack_info: false
};

rivets.bind($("#function-analysis"), 
	{analysis: analysis}
);

// assembly.line_info contains all the address to line info
function display_line_info(addr) {
	var left_bisect = assembly.line_info.filter(function(entry) {
		return parseInt(entry[0]) <= addr
	});
	console.log(left_bisect[left_bisect.length - 1]);
}

// get stack info from address
function get_stack_info(addr) {
	analysis.show_stack_info = false;

	// info from DIE
	$.ajax({
		type: "GET",
		url: URL_DIE_INFO + "?address=" + addr
	})
	.done(function(data) {
		if (data[0] == null) {
			analysis.stack_info = [["No stack info for this instruction", ""]]
		}
		else {
			analysis.stack_info = data
		}
		analysis.show_stack_info = true;
	});
}

function instructionClicked(e, model) {
	var addr = parseInt(model.i.address);
	showAnalysis();
	get_stack_info(addr);
	// display_line_info(model);
}

// display functions: show and hide analysis panel
var fullHeight = "97vh";
var partialHeight = "50vh";
$("#function-analysis").hide(); // init hide
function showAnalysis() {
	$("#function-analysis").show().height("30vh")
	$("#top-half").height(partialHeight);
}

function hideAnalysis() {
	$("#function-analysis").hide();
	$("#top-half").height(fullHeight);
}