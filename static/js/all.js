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


$(document).ready(function() {
	if ($("#file_selector").val() == "") {
		$("#file_submit").prop("disabled", true);
	}
	

	$("#file_selector").change(function(e) {
		if ($(this).val() == "") { // disable submit
			$("#file_submit").prop("disabled", true);
		}
		else { // enable submit
			$("#file_submit").prop("disabled", false);
		}
	});
});
var curr_index = 0;
var NUM_FUNCTIONS = 100;

$('#function-name-input').on('keyup', function() {
    console.log(this.value.length);
    console.log(this.value);
    if (this.value.length >= 1) {
        $.get('/get_substring_matches', { substring: this.value, start_index: 0, num_functions: NUM_FUNCTIONS } )
        .done(function(data) {
            clearFuncList();
            populateFuncList(data);
        })
        .fail(function() {
            alert("Unable to contact server.");
        })
        .always(function() {
            console.log("Request complete.");
        });
    }
});

function clearFuncList() {
    document.getElementById('functions').innerHTML = "";
}

function populateFuncList(data) {
    functions = document.getElementById('functions');
    for (i in data) {
        var newDiv = document.createElement('div');
        newDiv.className = 'function';
        newDiv.setAttribute('data-offset', data[i]['offset']);
        newDiv.setAttribute('data-size', data[i]['size']);
        var newSpan = document.createElement('span');
        newSpan.innerHTML = data[i]['name'];
        newDiv.appendChild(newSpan);
        functions.appendChild(newDiv);

    }
    registerFunctionHandler();
}

$('#button-prev').click(function() {
    curr_index -= NUM_FUNCTIONS;
    if (curr_index < 0) {
        curr_index = 0;
    }
    var input = document.getElementById('function-name-input');
    $.get('/get_substring_matches', { substring: this.value, start_index: curr_index, num_functions:100 } )
        .done(function(data) {
            clearFuncList();
            populateFuncList(data);
        })
        .fail(function() {
            alert("Unable to contact server.");
        })
        .always(function() {
            console.log("Request complete.");
        });
});

$('#button-next').click(function() {
    curr_index += NUM_FUNCTIONS;
    var input = document.getElementById('function-name-input');
    $.get('/get_substring_matches', { substring: this.value, start_index: curr_index, num_functions:100 } )
        .done(function(data) {
            clearFuncList();
            populateFuncList(data);
        })
        .fail(function() {
            alert("Unable to contact server.");
        })
        .always(function() {
            console.log("Request complete.");
        });
});
