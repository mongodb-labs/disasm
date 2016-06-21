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