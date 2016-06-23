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
			content = getFunctionDisasmHTML(data)
			$("#function-disasm").html(content);
		})
		.fail(function(data) {
			$("#function-disasm").html("Sorry, something went wrong!");
		});
	});
}


// given JSON of functions, return HTML string
function getFunctionDisasmHTML(instructions) {
	var res = "";
	
	instructions.forEach(function(i, index, arr) {
		var row = "<span class='row'><div class='address two columns'>0x" + i.address.toString(16) 
			+ "</div><div class='mnemonic two columns'>" + i.mnemonic 
			+ "</div><div class='op_str eight columns'>" + i.op_str
			+ "</div></span>";
		res += row;
	});
	return res;
}

