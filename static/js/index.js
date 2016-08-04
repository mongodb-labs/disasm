/* 
 * Copyright 2016 MongoDB Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


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

var show_error = $('#meta-data').attr("data-show-error") === "True";
rivets.bind($('#errors'), {show_error: show_error});