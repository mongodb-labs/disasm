// assembly.line_info contains all the address to line info
function instructionClicked(e, model) {
	var addr = model.i.address;

	var left_bisect = assembly.line_info.filter(function(entry) {
		return parseInt(entry[0]) <= parseInt(addr)
	});
	console.log(left_bisect[left_bisect.length - 1]);
}
