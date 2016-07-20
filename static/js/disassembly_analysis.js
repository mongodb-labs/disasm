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
	source_code: {},
};

var analysis_ctrl = {
	filepathClicked: filepathClicked,
	tabStackInfoClicked: tabStackInfoClicked,
	tabMnemonicDescClicked: tabMnemonicDescClicked
};

rivets.bind($("#function-analysis"), 
	{analysis: analysis, ctrl: analysis_ctrl}
);

// get stack info from address
function get_stack_info(addr) {
	$(".tab-content").hide();

	// info from DIE
	$.ajax({
		type: "GET",
		url: URL_DIE_INFO + "?address=" + addr
	})
	.done(function(data) {
		if (data == null || data[0] == null) {
			analysis.stack_info = [["No stack info for this instruction", ""]];
		}
		else {
			analysis.stack_info = data;
		}
		tabStackInfoClicked();

		// default to selecting first frame
		var first_frame = document.getElementsByClassName("stack-info-frame")[0];
		_filepathClicked(first_frame, analysis.stack_info[0][0], analysis.stack_info[0][1]);
	});
}

function instructionClicked(e, model) {
	var $target = $(e.target);
	if ($target.parents('.address').length) {
		addressClicked(e, model);
		return;
	}
	// http://stackoverflow.com/questions/17084839/check-if-any-ancestor-has-a-class-using-jquery
	else if ($target.parents('.mnemonic').length) {
		mnemonicClicked(e, model);
		return;
	}
	else if ($target.parents('.op_str').length) {
		opStrClicked(e, model);
		return;
	}

	var addr = parseInt(model.i.address);
	assembly.active_instruction = model.i.address;
	showAnalysis();
	jumpTo(model, model.i.address);
	get_stack_info(addr);
}

function tabStackInfoClicked(event, model) {
	$(".tab-content").hide();
	$(".tab-content.tab-stack-info").show();

	$(".tab").removeClass('active');
	$(".tab.tab-stack-info").addClass("active");
}

function tabMnemonicDescClicked(event, model) {
	$(".tab-content").hide();
	$(".tab-content.tab-mnemonic-desc").show();

	$(".tab").removeClass('active');
	$(".tab.tab-mnemonic-desc").addClass("active");
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
	assembly.active_instruction = "";
}

function showFullDescription(e, filename) {
	$('#full_desc').attr('src', filename);
	$('iframe#full-descript').contents().find("html").attr('font-size', '0.8em');
}


function filepathClicked(e, model) {
	_filepathClicked(e.currentTarget, model.frame[0], model.frame[1])
}

// when a particular filepath is clicked, triggering an api call
// to get the source code
function _filepathClicked(element, src_path, lineno) {
	$(".file-selected").removeClass("file-selected");
	element.classList.add("file-selected");

	$.ajax({
		type: "POST",
		url: URL_SOURCE_CODE,
		data: {
			"src_path": src_path,
			"lineno": lineno
		}
	})
	.done(function(data) {
		if (data.hasOwnProperty("target")) {
			analysis.source_code = {
				"before": data['before'],
				"target": data['target'],
				"after": data['after']
			}

			// source code syntax highlighting
			$(".source-code pre").each(function(i, block) {
				hljs.highlightBlock(block);
			});

			// scroll to relevant line
			var offsetTop = $('.source-code .target').height() * lineno - $('.source-code').height()/2;
			$('.source-code').scrollTop(offsetTop);
		}
		// sent a filepath from root /
		else {
			analysis.source_code = {
				"before": "Sorry, cannot get source code from this path",
				"target": "",
				"after": ""
			};
		}
	})
	// should never happen, but exists as a placeholder
	.fail(function() { 
		analysis.source_code = {
			"before": "Sorry, cannot get source code from this path",
			"target": "",
			"after": ""
		}
	});
}

