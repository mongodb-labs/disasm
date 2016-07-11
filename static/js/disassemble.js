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
                	var $rip = $(opt.$trigger.context);
                	$rip.find(".rip-default").removeAttr("hidden");
                	// Add hidden attribute to this. Will it make a duplicate???
                	$rip.find(".rip-resolved").attr("hidden", "hidden");
                	$rip.find(".rip-symbol").attr("hidden", "hidden");
                	// var ripBlock = opt.$trigger.context;
                	// var values = ripBlock.getAttribute("value");
                	// var offset = values.substring(0,values.indexOf(','));
                	// // This is the string we want, but we also need the hljs parsing.
                	// ripBlock.innerHTML = '[rip + ' + offset + ']';
                	// // Strip out the hljs elements in this instruction
                	// $(ripBlock.parentElement.parentElement).find('[class^=hljs]').each(function(i, elem) {
                	// 	$(elem).replaceWith($(elem).contents());
                	// });
                	// // Reprocess this line of assembly with hljs and the number-wrapping
                	// hljs.highlightBlock(ripBlock.parentElement.parentElement);
                	// wrapAllNumbers();
                	// // There's a weird bug where the context-menu-active class doesn't get removed,
                	// // even though the menu is gone, causing it to not be able to be right clicked
                	// // again. Easy fix. Just remove the class.
                	// $('.context-menu-active').removeClass('context-menu-active');
                }
            },
            decoded: {
                name: "Resolved Address",
                callback: function(key, opt) {
                	var $rip = $(opt.$trigger.context);
                	$rip.find(".rip-default").attr("hidden", "hidden");
                	$rip.find(".rip-resolved").removeAttr("hidden");
                	$rip.find(".rip-symbol").attr("hidden", "hidden");
                	// var ripBlock = opt.$trigger.context;
                	// var values = ripBlock.getAttribute("value");
                	// var address = values.substring(values.indexOf(',')+1, values.length);
                	// // This is the string we want, but we also need the hljs parsing.
                	// ripBlock.innerHTML = '[' + address + ']';
                	// // Strip out the hljs elements in this instruction
                	// $(ripBlock.parentElement.parentElement).find('[class^=hljs]').each(function(i, elem) {
                	// 	$(elem).replaceWith($(elem).contents());
                	// });
                	// // Reprocess this line of assembly with hljs and the number-wrapping
                	// hljs.highlightBlock(ripBlock.parentElement.parentElement);
                	// wrapAllNumbers();
                	// // There's a weird bug where the context-menu-active class doesn't get removed,
                	// // even though the menu is gone, causing it to not be able to be right clicked
                	// // again. Easy fix. Just remove the class.
                	// $('.context-menu-active').removeClass('context-menu-active');
                }
            },
            symbol: {
                name: "Referenced Symbol",
                callback: function(key, opt) {
                	var $rip = $(opt.$trigger.context);
                	$rip.find(".rip-default").attr("hidden", "hidden");
                	$rip.find(".rip-resolved").attr("hidden", "hidden");
                	$rip.find(".rip-symbol").removeAttr("hidden");
                	// This one's a bit more complicated. In order to 
                	// var ripBlock = opt.$trigger.context;
                	// var values = ripBlock.getAttribute("value");
                	// // var address = values.substring(values.indexOf(','), values.length);
                	// // ripBlock.innerHTML = address;
                	// console.log("Haaaa memes!");
                	// hljs.highlightBlock(ripBlock.parentElement.parentElement);
                	// wrapNumbers();

                	// $('.context-menu-active').removeClass('context-menu-active');
                }
            }
        }
        // callback: contextMenuConvertBase
    });
});


var URL_DISASM_FUNCTION = "/disasm_function";
var URL_LINE_INFO = "/get_line_info";
var URL_DIE_INFO = "/get_die_info";

var assembly = {
	contents : [], 
	line_info: [], 
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
	assembly.line_info = [];
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
	// get_function_line_info(begin, size);

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
				replacementStr += '<span class="rip-symbol" hidden>"' + i['rip-symbol'] + '"</span>';
				replacementStr += ']</span>';
				i.op_str = i.op_str.replace(/\[.*\]/, replacementStr);
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

// get line info for function
function get_function_line_info(begin, size) {
	$.ajax({
		type:"GET",
		url: URL_LINE_INFO + "?begin=" + begin + "&size=" + size
	})
	.done(function(data) {
		assembly.line_info = data;
		console.log(assembly.line_info)
	})
	.fail(function(data) {
		console.log("something went wrong in getting line info")
	});
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
