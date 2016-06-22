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
			$("#function-disasm").text(content);
		})
		.fail(function(data) {
			$("#function-disasm").text("Sorry, something went wrong!");
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

