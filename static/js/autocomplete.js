var curr_index = 0;
var NUM_FUNCTIONS = 100;

var functions = {contents: []}
rivets.bind($("#functions"), {functions: functions});

// search bar 
$('#function-name-input').on('keyup', function() {
    console.log(this.value.length);
    console.log(this.value);
    if (this.value.length >= 1) {
        $.get('/get_substring_matches', { substring: this.value, start_index: 0, num_functions: NUM_FUNCTIONS } )
        .done(function(funcs) {
            functions.contents = funcs;
        })
        .fail(function() {
            console.log("Unable to contact server.");
        })
        .always(function() {
            console.log("Request complete.");
        });
    }
});

// helper for pagination
function getNextPage(query) {
    var input = document.getElementById('function-name-input');
    $.get('/get_substring_matches', { substring: query, start_index: curr_index, num_functions:100 } )
        .done(function(funcs) {
            functions.contents = funcs;
        })
        .fail(function() {
            alert("Unable to contact server.");
        })
        .always(function() {
            console.log("Request complete.");
        });
}

$('#button-prev').click(function() {
    curr_index -= NUM_FUNCTIONS;
    if (curr_index < 0) {
        curr_index = 0;
    }
    getNextPage(this.value);
});

$('#button-next').click(function() {
    curr_index += NUM_FUNCTIONS;
    getNextPage(this.value);
});
