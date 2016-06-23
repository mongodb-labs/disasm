var URL_DISASM_FUNCTION = "/disasm_function"

var assembly = {contents : []};
rivets.bind($("#function-disasm"), {assembly: assembly});

function functionClicked(el) {
	data = {
		filename: $('h2.filename').text().trim(),
		funcname: $(el).text().trim(),
		offset: $(el).data("offset"),
		size: $(el).data("size")
	}

	$.ajax({
		type: "POST",
		url: URL_DISASM_FUNCTION,
		data: data
	})
	.done(function(data) {
		// change to hex
		data = data.map(function(i) {
			i.address = "0x" + i.address.toString(16);
			return i;
		});
		assembly.contents = data;
	})
	.fail(function(data) {
		$("#function-disasm").text("Sorry, something went wrong!");
	});
}
