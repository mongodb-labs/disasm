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

	// get addr -> line info from server
	// FOR NOW seems unnecessary? may need to bring it back if loading DIEs becomes excessively slow
	begin = el.attributes["data-st-value"].value;
	size = el.attributes["data-size"].value;

	// preload DIE info from server
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
		// change to hex
		assembly.data = data.map(function(i) {
			i.address = "0x" + i.address.toString(16);
			if ("rip" in i) {
				var replacementStr =  "";
				replacementStr += '<span class="rip">[';
				replacementStr += '<span class="rip-default">rip + ' + i['rip-offset'] + '</span>';
				replacementStr += '<span class="rip-resolved" hidden>' + i['rip-resolved'] + '</span>';
				replacementStr += '<span class="rip-value-ascii" hidden>"' + i['rip-value-ascii'] + '"</span>';
				replacementStr += '<span class="rip-value-hex" hidden>' + i['rip-value-hex'] + '</span>';
				if (i['rip-symbol']) {
					replacementStr += '<span class="rip-symbol" hidden>' + i['rip-symbol'] + '</span>';
				}
				replacementStr += ']</span>';
				i.op_str = i.op_str.replace(/\[.*\]/, replacementStr);
			}
			if ("nop" in i) {
				// Ask Mathias if 10-byte NOPs exist
				i.op_str = i.size + " bytes";
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

		wrapAllNumbers();

		// $('.hljs-built_in').each(function(index, elem) {
		// 	if (elem.innerHTML === "rip") {
		// 		console.log("Memes!");
		// 		var line = elem.parentElement;
		// 		// Brackets that contain "rip" and the offset, eg. "[rip + 0x123456]"
		// 		var ripBlock = line.innerHTML.substring(line.innerHTML.indexOf('['), line.innerHTML.indexOf(']')+1);
		// 		// Address of the following instruction
		// 		var rip = elem.parentElement.parentElement.nextSibling.children[0].children[0].innerHTML;
		// 		// Offset from rip
		// 		var offset = elem.nextSibling.nextSibling.innerHTML;
		// 		// Actual value referred to in ripBlock. Obtained by adding offset to rip
		// 		var value = '0x' + (parseInt(rip, 16) + parseInt(offset, 16)).toString(16);
		// 		line.innerHTML = line.innerHTML.replace(/\[.*\]/, '<span class="rip" value="' + offset + ',' + value + '">' + ripBlock + '</span>');
		// 	}
		// });
	})
	.fail(function(data) {
		console.log("Request failed");
	});
}

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

function wrapHexAndDec(str) {
	var outputStr = "";
	// http://stackoverflow.com/questions/1966476/javascript-process-each-letter-of-text
	for(var i = 0, c=''; c = str.charAt(i); i++){ 
		// Hex string located
 		if (c == '0' && str.charAt(i+1) == 'x') {
 			var hexString = '0x';
 			for (i += 2; (c = str.charAt(i)) && isHexChar(c); i++) {
 				hexString += c;
 			}
 			outputStr += '<span class="number" value="hex">' + hexString + '</span>';
 			i--;
 		}
 		// Decimal string located
 		else if (c >= '1' && c <= '9') {
 			var decimalString = "";
 			for (; (c = str.charAt(i)) && ( c >= '0' && c <= '9' ); i++) {
 				decimalString += c;
 			}
 			outputStr += '<span class="number" value="twosCompDec64">' + decimalString + '</span>';
 			i--;
 		}
 		else {
 			outputStr += c;
 		}
 	}
	return outputStr;
}

function isHexChar(char) {
	return (char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F');
}
