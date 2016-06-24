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

var URL_DISASM_FUNCTION = "/disasm_function"

function registerFunctionHandler() {
	console.log("registering handlers for when a function is clicked on");
	$("#functions .function").click(function(e) {
		// data about function 
		console.log("Function clicked");
		data = {
			filename: $('h2.filename').text().trim(),
			funcname: $(this).text().trim(),
			offset: $(this).data("offset"),
			size: $(this).data("size")
		}

		// send to server
		$.ajax({
			type: "POST",
			url: URL_DISASM_FUNCTION,
			data: data
		})
		.done(function(data) {
			content = getFunctionDisasmHTML(data);
			$("#function-disasm").html(content);
			// registerHexHandler($(".hex-string"));
			// registerDecHandler($(".decimal-string"));
		})
		.fail(function(data) {
			$("#function-disasm").html("Sorry, something went wrong!");
		});
	});
}

$(function() {
	$.contextMenu({
		selector: '.number',
		items: {
			hex: {
				name: "Hexadecimal"
				//callback: contextMenuHex
			},
			decimal: {
				name: "Decimal"
				//callback: contextMenuDec
			},
			unsignedBinary: {
				name: "Unsigned Binary"
				//callback: contextMenuUnsignedBinary
			},
			signedBinary: {
				name: "Signed Binary"
				//callback: contextMenuSignedBinary
			}
		},
		callback: contextMenuConvertBase
	});
});

function contextMenuConvertBase(key, opt) {
	var base = opt.$trigger.context.value;
	var radix;
	switch(base) {
		case "hex":
			radix = 16;
			break;
		case "decimal":
			radix = 10;
			break;
		case "signedBinary":
		case "unsignedBinary":
			radix = 2;
			break;
	}
	var oldValue = parseInt(opt.$trigger.context.innerHTML, radix);
	switch(key) {
		case "hex": 
			radix = 16;
			break;
		case "decimal":
			radix = 10;
			break;
		case "signedBinary":
		case "unsignedBinary":
			radix = 2;
			break;
	}
	opt.$trigger.context.value = key;
	var newValue = oldValue.toString(radix);
	if (key == "hex") {
		newValue = "0x" + newValue;
	}
	opt.$trigger.context.innerHTML = newValue;
	console.log("Converted " + base + " number " + oldValue + " to " + key + " number " + newValue);
}

function contextMenuHex(key, opt) {
	console.log("Menu item: hex");
	return true;
}

function contextMenuDec(key, opt) {
	console.log("Menu item: dec");
	return true;
}

function contextMenuUnsignedBinary(key, opt) {
	console.log("Menu item: us bin");
	return true;
}

function contextMenuSignedBinary(key, opt) {
	console.log("Menu item: s bin");
	return true;
}

// given JSON of functions, return HTML string
function getFunctionDisasmHTML(instructions) {
	var res = "";
	
	instructions.forEach(function(i, index, arr) {
		i.op_str = wrapHexAndDec(i.op_str);
		var row = "<span class='row'><div class='address two columns'>0x" + i.address.toString(16) 
			+ "</div><div class='mnemonic two columns'>" + i.mnemonic 
			+ "</div><div class='op_str eight columns'>" + i.op_str
			+ "</div></span>";
		res += row;
	});
	return res;
}

function wrapHexAndDec(str) {
	var outputStr = "";
	// http://stackoverflow.com/questions/1966476/javascript-process-each-letter-of-text
	for(var i = 0, c=''; c = str.charAt(i); i++){ 
		// Hex string located
 		if (c == '0' && str.charAt(i+1) == 'x') {
 			var hexString = '0x';
 			for (i += 2; (c = str.charAt(i)) && isHexChar(i); i++) {
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
 			outputStr += '<span class="number" value="decimal">' + decimalString + '</span>';
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