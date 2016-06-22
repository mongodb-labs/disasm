var URL_DISASM_FUNCTION = "/disasm_function"

$("#functions .function").click(function(e) {
	// data about function 
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
		$("#function-disasm").html(content)
	})
	.fail(function(data) {
		$("#function-disasm").html("Sorry, something went wrong!")
	});
});


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
$('#function-name-input').on('keyup', function() {
    if (this.value.length >= 1) {
        $.get('http://localhost:5000/get_substring_matches', { substring: this.value } )
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
}