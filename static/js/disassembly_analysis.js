URL_INSTRUC_TO_LINE = "/get_line_info"

function instructionClicked(e, model) {
	// get address from item
	var addr = parseInt(model.i.address, 16);

	$.ajax({
		type: "GET",
		url: URL_INSTRUC_TO_LINE + "?addr=" + addr
	})
	.done(function(data) {
		console.log(data); // returns filename, line
	})
	.fail(function(data) {
		console.log("uhhh something went wrong");
	});
}
