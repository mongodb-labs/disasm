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

$(function() {
    $.contextMenu({
        selector: '.rip',
        items: {
            rip: {
                name: "Rip Relative",
                callback: function(key, opt) {
                	ripCallback(key, opt, '.rip-default');
                }
            },
            decoded: {
                name: "Resolved Address",
                callback: function(key, opt) {
                	ripCallback(key, opt, '.rip-resolved');

                }
            },
            value_ascii: {
                name: "Referenced Value (ASCII)",
                callback: function(key, opt) {
                	ripCallback(key, opt, '.rip-value-ascii');

                }
            },
            value_hex: {
            	name: "References Value (Hex)",
            	callback: function(key, opt) {
            		ripCallback(key, opt, '.rip-value-hex');
            	}
            },
            symbol: {
            	name: "Symbol",
            	callback: function(key, opt) {
            		ripCallback(key, opt, '.rip-symbol');
            	},
            	disabled: function(key, opt) {
            		// We want to show this item iff the rip-symbol element exists
            		console.log($(opt.$trigger.context).find('.rip-symbol').length);
            		return $(opt.$trigger.context).find('.rip-symbol').length == 0;
            	}
            }
        }
    });
});

function ripCallback(key, opt, classToShow) {
	var $rip = $(opt.$trigger.context);
	$rip.find("[class^='rip-']").attr("hidden", "hidden");
	$rip.find(classToShow).removeAttr("hidden");
}


var URL_DISASM_FUNCTION = "/disasm_function";
var URL_DIE_INFO = "/get_die_info";

var assembly = {
	contents : [], 
	func_name: "", 
	instructions_loading: false
};
var assembly_ctrl = {
	instructionClicked: instructionClicked // in disassembly_analysis
}
rivets.bind($("#function-disasm"), 
	{assembly: assembly, ctrl: assembly_ctrl}
);

// for arrows (jump highlighting)
var svg = d3.select('#function-disasm .jump-arrows')
	.append('svg:svg')
	.attr('width', '100%');

svg.append('svg:defs').selectAll('marker')
	// create arrowhead
	.data(['arrow'])
	.attr('id', String)
	.enter().append('svg:marker')
	.attr('viewBox', "0 0 10 10")
	.attr('markerWidth', 13)
	.attr('markerHeight', 13)
	.attr('orient', 'auto')
	.attr('refX', 10)
	.attr('refY', 10)
	.append('svg:path')
	.attr('d', "M0,-5L10,0L0,5");

function functionClicked(event, model) {
	// handle expansion/collapse of <> in function name
	var el = event.currentTarget;
	if (event.target.classList.contains("expandable")) {
		expandFunctionName(event, model);
		return;
	}
	else if (event.target.classList.contains("collapsable")) {
		collapseFunctionName(event, model);
		return;
	}

	// clear all info
	assembly.func_name = "";
	assembly.contents = [];
	hideAnalysis();

	// set class to active and indicate func name
	$(".selected").removeClass("selected");
	el.classList.add("selected");
	assembly.func_name = el.innerText;

	// activate loading icon
	assembly.instructions_loading = true;
	
	// get function assembly from server
	disassemble_function(el);
	
	// preload DIE info from server
	begin = el.attributes["data-st-value"].value;
	$.ajax({
		type: "GET",
		url: URL_DIE_INFO + "?address=" + begin
	});
}

// get assembly for given function, given as DOM element
function disassemble_function(el) {
	// disassemble function
	data_disassemble = {
		filename: $('h2.filename').text().trim(),
		func_name: el.innerText,
		st_value: el.attributes["data-st-value"].value,
		file_offset: el.attributes["data-offset"].value,
		size: el.attributes["data-size"].value
	}

	$.ajax({
		type: "POST",
		url: URL_DISASM_FUNCTION,
		data: data_disassemble
	})
	.done(function(data) {
		// Process each line of assembly
		assembly.data = data.map(function(i) {
			i.address = "0x" + i.address.toString(16);
			if ("rip" in i) {
				var replacementStr =  "";
				replacementStr += '<span class="rip">[';
				replacementStr += '<span class="rip-default">rip + ' + i['rip-offset'] + '</span>';
				replacementStr += '<span class="rip-resolved" hidden>' + i['rip-resolved'] + '</span>';
				replacementStr += '<span class="rip-value-ascii" hidden>"' + i['rip-value-ascii'] + '"</span>';
				replacementStr += '<span class="rip-value-hex" hidden>' + i['rip-value-hex'] + '</span>';
				replacementStr += ']</span>';
				i.op_str = i.op_str.replace(/\[.*\]/, replacementStr);
			}
			else if ("nop" in i) {
				i.op_str = i.size + " bytes";
			}

			if (i['comment']) {
				i.op_str += '<span class="comment"> # ' + i['comment'] + '</span>';
			}
			return i;
		});

		// clear loading icon
		assembly.instructions_loading = false;
		assembly.contents = data;

		// syntax highlighting
		$(".instructions span.row.instruction").each(function(i, block) {
			hljs.highlightBlock(block);
		});

		// load jump info
		handleJumpHighlighting();

		// Adds a "hex" or "twosCompDec64" class to all numbers
		wrapAllNumbers();
	})
	.fail(function(data) {
		console.log("Request failed");
	});
}

// display jump arrows
function handleJumpHighlighting() {
	// load jump info
	var reverseJumps = {}
	for (var i = 0; i < assembly.contents.length; i++) {
		var line = assembly.contents[i];
		if (line.mnemonic.charAt(0) == 'j' && line.op_str in reverseJumps) {
			reverseJumps[line.op_str].push(line.address)
		}
		else if (line.mnemonic.charAt(0) == 'j' && !(line.op_str in reverseJumps)) {
			reverseJumps[line.op_str] = [line.address]
		}
	}

	// load into assembly.contents
	assembly.contents = assembly.contents.map(function(line) {
		if (line.mnemonic.charAt(0) == 'j') {
			line['jumpTo'] = line.op_str;
		}
		if (line.address in reverseJumps) {
			line['jumpFrom'] = reverseJumps[line.address]
		}
		return line
	});

	// build array of { from: <addr>, to: <addr> }
	var jumps = [];
	assembly.contents.map(function(line) {
		var vert_offset = 12;
		if (line.mnemonic.charAt(0) == 'j') {
			jumps.push({
				"from": line.address,
				"fromY": document.getElementById(line.address).offsetTop + vert_offset,
				"to": line.op_str,
				"toY": document.getElementById(line.op_str).offsetTop + vert_offset
			});
		}
	});

	// actually draw arrows
	var instructions = document.getElementsByClassName('instructions')[0];
	svg.attr('height', instructions.clientHeight);
	var arrow = svg.append('svg:g')
		.attr('transform', function(jump, i) {
			var width = document.getElementsByClassName('jump-arrows')[0].clientWidth;
			return 'scale(-1, 1) translate(-' + width + ', 0)';
		})
		.selectAll('path')
		.data(jumps)
		// create curved lines
		.enter().append('svg:path')
		.attr('d', function(jump, i) {
			var x = 2;
			var command = "M" + x + " " + jump.fromY + " " +
				"C " + (x+15) + " " + jump.fromY + ", " +
		 		(x+15) + " " + jump.toY + ", " +
		 		x + " " + jump.toY;
		 	return command;
		})
		.attr('marker-end', "url(#arrow)");
}

// wrap numbers for base changes etc.
function wrapAllNumbers() {
	$('.hljs-number').each(function(index, elem) {
		wrapNumbersInElem(elem);
	});
}

function wrapNumbersInElem(elem) {
	var charOne = elem.innerHTML.charAt(0);
	var charTwo = elem.innerHTML.charAt(1);
	if (charOne == '0' && charTwo == 'x') {
		// elem.className += ' hex';
		elem.setAttribute('value', 'hex');
	}
	else if (charOne >= '0' && charTwo <= '9') {
		elem.setAttribute('value', 'twosCompDec64');
	}
	else {
		console.log("Unknown data type:");
		console.log(elem);
	}
}
