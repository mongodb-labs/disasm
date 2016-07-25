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

var functionList = document.getElementById('functions');

var listener = new window.keypress.Listener();
listener.register_many([
    {
        "keys"          : "up",
        "on_keydown"    : function() {
            if (selectedFunction) {
                var prev = selectedFunction.previousSibling;
                if (prev && $(prev).hasClass('function')) {
                    $(selectedFunction).removeClass('selected');
                    $(prev).addClass('selected');
                    selectedFunction = prev;
                }

                // If the selected element is off-screen, scroll s.t. the selected element is at the 
                // to of the function list.
                var selectedTop = selectedFunction.getBoundingClientRect().top;
                var selectedBot = selectedFunction.getBoundingClientRect().bottom;
                var functionsTop = functionList.getBoundingClientRect().top;
                var functionsBot = functionList.getBoundingClientRect().bottom;
                if (selectedTop < functionsTop || selectedBot > functionsBot) {
                    functionList.scrollTop += selectedTop - functionsTop;
                }
            }
        }
    },
    {
        "keys"          : "down",
        "on_keydown"    : function() {
            if (selectedFunction) {
                var next = selectedFunction.nextSibling;
                if (next && $(next).hasClass('function')) {
                    $(selectedFunction).removeClass('selected');
                    $(next).addClass('selected');
                    selectedFunction = next;
                }
                // If the selected element is off-screen, scroll s.t. the selected element is at the 
                // bottom of the function list.
                var selectedTop = selectedFunction.getBoundingClientRect().top;
                var selectedBot = selectedFunction.getBoundingClientRect().bottom;
                var functionsTop = functionList.getBoundingClientRect().top;
                var functionsBot = functionList.getBoundingClientRect().bottom;
                if (selectedBot > functionsBot || selectedTop < functionsTop) {
                    functionList.scrollTop += selectedBot - functionsBot;
                }
            }
        }
    },
    {
        "keys"         : "enter",
        "on_keydown"   : function() {
            if (selectedFunction) {
                window.location = selectedFunction.href;
            }
        }
    },
]);

var helpListener = new window.keypress.Listener();
helpListener.simple_combo('?', function() {
    console.log("Only when outside the text box");
})
$('input[type=text]')
    .bind("focus", function() { helpListener.stop_listening(); })
    .bind("blur", function() { helpListener.listen(); });