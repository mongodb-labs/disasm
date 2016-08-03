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
                functionsOnUp(functionList);
            }
        }
    },
    {
        "keys"          : "down",
        "on_keydown"    : function() {
            if (selectedFunction) {
                functionsOnDown(functionList);
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


$('input[type=text]')
    .bind("focus", function() { globalListener.stop_listening(); })
    .bind("blur", function() { globalListener.listen(); });

    