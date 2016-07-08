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

var URL_SOURCE_CODE = "/source_code_from_path";

var analysis = {
	stack_info: [],
	show_stack_info: false,
	source_code: {}
};

var analysis_ctrl = {
	filepathClicked: filepathClicked
};

rivets.bind($("#function-analysis"), 
	{analysis: analysis, ctrl: analysis_ctrl}
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
	$(".instruc-selected").removeClass("instruc-selected");
	e.currentTarget.classList.add("instruc-selected");

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
	$("#function-analysis").show();
	$("#top-half").height(partialHeight);
}

function hideAnalysis() {
	$(".instruc-selected").removeClass("instruc-selected");
	$("#function-analysis").hide();
	$("#top-half").height(fullHeight);
}

function filepathClicked(e, model) {
	var width = 10;

	$.ajax({
		type: "POST",
		url: URL_SOURCE_CODE,
		data: {
			"src_path": model.frame[0],
			"lineno": model.frame[1],
			"width": width
		}
	})
	.done(function(data) {
		analysis.source_code = {
			"before": data['before'],
			"target": data['target'],
			"after": data['after']
		}

		// source code syntax highlighting
		$(".source-code pre").each(function(i, block) {
			hljs.highlightBlock(block);
		});
	});
}

