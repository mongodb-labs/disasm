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
	active_instruction: "",
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

svg.append('svg:defs')
	// create arrowhead
	.append('svg:marker')
	.attr({
		'id': 'arrow',
    "viewBox": "0 -5 10 10",
    "refX": 8,
    "refY": 0,
    "markerWidth": 4,
    "markerHeight": 4,
    "orient": "auto",
    "fill": "gray",
	})
	.append('svg:path')
	.attr("d", "M0,-5L10,0L0,5");

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

	// set class to active and indicate func name
	$(".selected").removeClass("selected");
	el.classList.add("selected");

	// activate loading icon
	assembly.instructions_loading = true;

	// get addr -> line info from server
	// FOR NOW seems unnecessary? may need to bring it back if loading DIEs becomes excessively slow
	begin = el.attributes["data-st-value"].value;
	size = el.attributes["data-size"].value;
	
	// get function assembly from server
	return _disassemble_function(el);
}

function _disassemble_function(el) {
	return disassemble_function(
		el.innerText, 
		el.attributes["data-st-value"].value, 
		el.attributes["data-offset"].value,
		el.attributes["data-size"].value);
}

// get assembly for given function, given as DOM element
function disassemble_function(func_name, st_value, file_offset, size) {
	console.log("Function name: " + func_name);
	console.log("Address: " + st_value);
	console.log("Offset: " + file_offset);
	console.log("Size: " + size);

	// clear all info
	assembly.func_name = "";
	assembly.contents = [];
	svg.selectAll('g').remove();
	hideAnalysis();

	assembly.func_name = func_name;

	// disassemble function
	data_disassemble = {
		filename: $('h2.filename').text().trim(),
		func_name: func_name,
		st_value: st_value,
		file_offset: file_offset,
		size: size
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
			if (i['rip']) {
				var replacementStr =  "";
				replacementStr += '<span class="rip">[';
				replacementStr += '<span class="rip-default">rip + ' + i['rip-offset'] + '</span>';
				replacementStr += '<span class="rip-resolved" hidden>' + i['rip-resolved'] + '</span>';
				replacementStr += '<span class="rip-value-ascii" hidden>"' + i['rip-value-ascii'] + '"</span>';
				replacementStr += '<span class="rip-value-hex" hidden>' + i['rip-value-hex'] + '</span>';
				replacementStr += ']</span>';
				i.op_str = i.op_str.replace(/\[.*\]/, replacementStr);
			}
			else if (i['nop']) {
				i.op_str = i.size + " bytes";
			}
			else if (i['external-jump']) {
				var addr = i.op_str
				i.op_str = '<a href="#" onclick="disassemble_function(';
				i.op_str += '\'' + i['jump-function-name'] + '\',';
				i.op_str += i['jump-function-address'] + ',';
				i.op_str += i['jump-function-offset'] + ',';
				i.op_str += i['jump-function-size'];
				i.op_str += ')">' + addr + '</a>';
				// )" ';
				// i.op_str += 'data-st-value="' + i['jump-function-address'] + '" ';
				// i.op_str += 'data-offset="' + i['jump-function-offset'] + '" ';
				// i.op_str += 'data-size="' + i['jump-function-size'] + '" ';
				// i.op_str += '>' + addr + '</a>';
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

		// preload DIE info from server
		$.ajax({
			type: "GET",
			url: URL_DIE_INFO + "?address=" + st_value
		});
	})
	.fail(function(data) {
		console.log("Request failed");
	});

	return false;
}

// display jump arrows
function handleJumpHighlighting() {
	// load jump info
	var reverseJumps = {}
	for (var i = 0; i < assembly.contents.length; i++) {
		var line = assembly.contents[i];
		if (line['internal-jump'] && line['jump-address'] in reverseJumps) {
			reverseJumps[line['jump-address']].push(line.address)
		}
		else if (line['internal-jump'] && !(line['jump-address'] in reverseJumps)) {
			reverseJumps[line['jump-address']] = [line.address]
		}
	}

	// load into assembly.contents
	assembly.contents = assembly.contents.map(function(line) {
		if (line['internal-jump']) {
			line['jumpTo'] = [line['jump-address']]; // arr to future-proof
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
		if (line['internal-jump'] && document.getElementById(line['jump-address'])) {
			jumps.push({
				"from": line.address,
				"fromY": document.getElementById(line.address).offsetTop + vert_offset,
				"to": line['jump-address'],
				"toY": document.getElementById(line['jump-address']).offsetTop + vert_offset
			});
		}
	});

	// actually draw arrows
	var instructions = document.getElementsByClassName('instructions')[0];
	var svg_height = instructions.clientHeight;
	var svg_width = document.getElementsByClassName('jump-arrows')[0].clientWidth;
	
	svg.attr('height', svg_height);
	svg.append('svg:g')
		.attr('transform', function(jump, i) {
			return 'scale(-1, 1) translate(-' + svg_width + ', 0)';
		})
		.selectAll('path')
		.data(jumps)
		.enter().append('svg:path')
		.attr('d', function(jump, i) {
			var x = 5;
			var ext = (svg_width - x - 5) * (Math.abs(jump.fromY - jump.toY)/svg_height);
			ext = Math.max(5, ext);

			var command = "M" + x + " " + jump.fromY + " " +
				"h " + (x+ext) + " " + 			// diff horizontally
				"V " + jump.toY + " " + 		// vertical location
				"h " + (-(x+ext)) + " " 		// diff horizontally
		 	return command;
		})
		.attr('marker-end', "url(#arrow)")
		.attr('opacity', 0.3)
		.attr('stroke', "gray");
		

		attachInstructionHandlers(jumps);
}

// highlight the mouseover-ed or clicked jump
function attachInstructionHandlers(jumps) {
	$(".row.instruction").on("mouseenter", function(event) {
		var instruc = event.currentTarget;
		highlightJumpArrows(jumps, instruc.id);
	});

	$(".row.instruction").on("click", function(event) {
		var instruc = event.currentTarget;
		assembly.active_instruction = event.currentTarget.id;
		highlightJumpArrows(jumps, instruc.id);
	});
}


function highlightJumpArrows(jumps, instruc_id) {
	var instr_active = assembly.active_instruction;

	// highlight if has jump
	svg.selectAll('g path')
		.data(jumps)
		.attr('opacity', function(jump, b) {
			if (jump['from'] == instr_active || jump['to'] == instr_active) {
				return 1;
			}
			else if (jump['from'] == instruc_id || jump['to'] == instruc_id) {
				return 1;
			}
			else {
				return 0.3;
			}
		})
		.attr('stroke', function(jump, b) {
			if (jump['from'] == instr_active || jump['to'] == instr_active) {
				return "rgb(3,169,244)";
			}
			if (jump['from'] == instruc_id || jump['to'] == instruc_id) {
				return "rgb(41,182,246)";
			}
			else {
				return "gray";
			}
		});
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
