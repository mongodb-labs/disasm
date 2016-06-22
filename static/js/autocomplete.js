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
