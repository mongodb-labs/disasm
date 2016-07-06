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

var hexToBinMap = {
	"0": "0000",
	"1": "0001",
	"2": "0010",
	"3": "0011",
	"4": "0100",
	"5": "0101",
	"6": "0110",
	"7": "0111",
	"8": "1000",
	"9": "1001",
	"a": "1010",
	"A": "1010",
	"b": "1011",
	"B": "1011",
	"c": "1100",
	"C": "1100",
	"d": "1101",
	"D": "1101",
	"e": "1110",
	"E": "1110",
	"f": "1111",
	"F": "1111"
}

var binToHexMap = {
	"0000": "0",
	"0001": "1",
	"0010": "2",
	"0011": "3",
	"0100": "4",
	"0101": "5",
	"0110": "6",
	"0111": "7",
	"1000": "8",
	"1001": "9",
	"1010": "A",
	"1011": "B",
	"1100": "C",
	"1101": "D",
	"1110": "E",
	"1111": "F"
}

$(function() {
	$.contextMenu({
		selector: '.number',
		items: {
			hex: {
				name: "Hexadecimal"
			},
			unsignedDec64: {
				name: "64-bit Unsigned Decimal"
			},
			twosCompDec64: {
				name: "64-bit Signed 2's Complement Decimal"
			},
			binary: {
				name: "Binary"
			}
		},
		callback: contextMenuConvertBase
	});
});

function contextMenuConvertBase(key, opt) {
	var base = opt.$trigger.context.getAttribute("value");
	if (key == base) {
		console.log("Number is unchanged");
		return;	
	}
	// var radix;
	var binString;
	var startVal = opt.$trigger.context.innerHTML;
	var newVal;
	switch(base) {
		case "hex":
			binString = hexToBin(startVal);
			break;
		case "unsignedDec64":
			binString = unsignedDecToBin(startVal, 64);
			break;
		case "twosCompDec64":
			binString = signedDecToBin(startVal, 64);
			break;
		case "binary":
			binString = startVal;
			break;
		default:
			throw new Error("Unexpected base type: " + base);
	}
	switch (key) {
		case "hex":
			newVal = binToHex(binString);
			break;
		case "unsignedDec64":
			newVal = binToUnsignedDec(binString, 64);
			break;
		case "twosCompDec64":
			newVal = binToSignedDec(binString, 64);
			break;
		case "binary":
			newVal = binString;
			break;
		default:
			throw new Error("Unexpected key type: " + key);
	}
	opt.$trigger.context.setAttribute("value", key);
	if (key == "hex") {
		newVal = "0x" + newVal;	
	}
	opt.$trigger.context.innerHTML = newVal;
	console.log("Converted " + base + " number " + startVal + " to binary number " + binString + " to " + key + " number " + newVal);
}

function hexToBin(val) {
	var binStr = ""
	for (var i = 2; i < val.length; i++) {
		binStr += hexToBinMap[val.charAt(i)];
	}
	return binStr;
}

function binToHex(val) {
	var hexStr = "";
	// Make the binary string length divisible by 4 by prepending it with 0's
	for (var i = val.length % 4; i > 0; i--) {
		val = "0" + val;
	}
	for (var i = 0; i < val.length; i += 4) {
		hexStr += binToHexMap[val.substring(i, i+4)];
	}
	return hexStr;
}

function unsignedDecToBin(val, bits) {
	var decVal = BigInteger(val);
	var divRem;
	var binVal = "";
	for (var i = 0; i < bits; i++) {
		divRem = decVal.divRem(2);
		binVal = divRem[1] + binVal;
		decVal = divRem[0];
	}
	return binVal;
}

function binToUnsignedDec(val, bits) {
	var decVal = BigInteger.ZERO;
	for (var i = bits - val.length; i > 0; i--) {
		val = "0" + val;
	}
	// http://stackoverflow.com/questions/10258828/how-to-convert-binary-string-to-decimal
	return val.split('').reverse().reduce(function(x,y,i) {
		return (y === '1') ? x.add(BigInteger(2).pow(i)) : x;
	}, BigInteger.ZERO).toString();
}

function signedDecToBin(val, bits) {
	var negative = false;
	if (val.charAt(0) == '-') {
		negative = true;
		val = val.substring(1,substring.length);
	}
	var unsignedBinVal = unsignedDecToBin(val, bits);
	var twosCompBin = negative ? applyTwosCompConversion(unsignedBinVal) : unsignedBinVal;
	return twosCompBin;
}

function binToSignedDec(val, bits) {
	var signBit = val.charAt(0);
	var unsignedBinVal = "";
	for (var i = bits - val.length; i > 0; i--) {
		val = signBit + val;
	}
	var unsignedBinVal = signBit == "1" ? applyTwosCompConversion(val) : val;
	return (signBit == "1" ? "-" : "") + binToUnsignedDec(unsignedBinVal, bits);
}

function applyTwosCompConversion(val) {
	var i;
	var carried = false;
	var converted = "";
	for (i = val.length-1; i >= 0; i--) {
		if (val.charAt(i) == "1") {
			if (carried)
				converted = "0" + converted;
			else {
				converted = "1" + converted;
				carried = true;
			}
		} 
		else {
			if (carried)
				converted = "1" + converted;
			else
				converted = "0" + converted;
		}
	}
	return converted;
}

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
	begin = el.attributes["data-st-value"].value;
	size = el.attributes["data-size"].value;
	get_function_line_info(begin, size);

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
		data = data.map(function(i) {
			i.address = "0x" + i.address.toString(16);
			i.op_str =wrapHexAndDec(i.op_str);
			return i;
		});

		// clear loading icon
		assembly.instructions_loading = false;
		assembly.contents = data;
	})
	.fail(function(data) {
		console.log("Request failed");
	});
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
