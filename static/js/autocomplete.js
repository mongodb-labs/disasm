$('#function-name-input').on('keyup', function() {
    if (this.value.length >= 1) {
        $.get('http://localhost:5000/get_substring_matches', { substring: this.value } )
        .done(function(data) {
            console.log(data);
        })
        .fail(function() {
            alert("Unable to contact server.");
        })
        .always(function() {
            console.log("Request complete.");
        });
    }
});