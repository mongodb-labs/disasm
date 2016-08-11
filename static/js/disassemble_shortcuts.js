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

var instructionList = document.getElementById('function-disasm');
var functionList = document.getElementById('functions');

var mainListener = new window.keypress.Listener();
mainListener.register_many([
    {
        "keys"          : "up",
        "on_keydown"    : function() {
            var selectedInstruction = document.getElementById(assembly.active_instruction);
            if (selectedInstruction) {
                var prev = selectedInstruction.previousSibling;
                if (prev && $(prev).hasClass('instruction')) {
                    selectedInstruction = prev;
                }
                jumpTo(selectedInstruction.id);
                if (analysisVisible) {
                    updateAnalysis();
                }

            }
        },
        "is_solitary": true
    },
    {
        "keys"          : "down",
        "on_keydown"    : function() {
            var selectedInstruction = document.getElementById(assembly.active_instruction);
            if (selectedInstruction) {
                var next = selectedInstruction.nextSibling;
                if (next && $(next).hasClass('instruction')) {
                    selectedInstruction = next;
                }
                jumpTo(selectedInstruction.id);
                if (analysisVisible) {
                    updateAnalysis();
                }
            }
        },
        "is_solitary": true
    },
    {
        "keys"          : "left",
        "on_keydown"    : function() {
            history.back();
        }
    },
    {
        "keys"          : "right",
        "on_keydown"    : function() {
            var selectedInstruction = document.getElementById(assembly.active_instruction);
            if (selectedInstruction) {
                var model = assembly.contents[selectedInstruction.getAttribute('data-index')];
                if (model['internal-jump']) {
                    internalJump(model['jump-address']);
                }
                else if (model['external-jump']) {
                    var jumpLocation = $(selectedInstruction).find('a')[0];
                    if (jumpLocation) {
                        window.location.hash = assembly.active_instruction;
                        window.location = jumpLocation.href;
                    }
                }
                else if (model['return']) {
                    returning = true;
                    history.back();
                }
            }
        }
    },
    {
        "keys"          : "enter",
        "on_keydown"    : function() {
            var selectedInstruction = document.getElementById(assembly.active_instruction)
            if (selectedInstruction) {
                jumpTo(selectedInstruction.id);
                updateAnalysis();
                showAnalysis()
            }
        }
    },
    {
        "keys"          : "tab",
        "on_keydown"    : function() {
            if (analysisVisible) {
                var activeTab = $('.tab.active')[0];
                var next = activeTab.nextElementSibling;
                if (next && $(next).hasClass('tab')) {
                    next.click();
                }
                else {
                    $('.tabs').children()[0].click();
                }
            }
        }
    },
    {
        "keys"          : "shift up",
        "on_keydown"    : function() {
            if (analysisVisible && $('.tab.active').hasClass('tab-stack-info')) {
                var selectedPath = $('.stack-info-frame.file-selected')[0];
                var prev = selectedPath.previousElementSibling;
                if (prev && $(prev).hasClass('stack-info-frame')) {
                    prev.click();
                }
                else {
                    var stack_info_frames = $('.stack-info').children();
                    stack_info_frames[stack_info_frames.length-1].click();
                }
            }
        }
    },
    {
        "keys"          : "shift down",
        "on_keydown"    : function() {
            if (analysisVisible && $('.tab.active').hasClass('tab-stack-info')) {
                var selectedPath = $('.stack-info-frame.file-selected')[0];
                var next = selectedPath.nextElementSibling;
                if (next && $(next).hasClass('stack-info-frame')) {
                    next.click();
                }
                else {
                    var stack_info_frames = $('.stack-info').children();
                    stack_info_frames[0].click();
                }
            }
        }
    },
    {
        "keys"          : "esc",
        "on_keyup"     : function() {
            hideAnalysis();
            hideJumptable();
        }
    },
]);

var functionSearchListener = new window.keypress.Listener();
functionSearchListener.register_many([
    {
        "keys"          : "up",
        "on_keydown"    : function() {
            functionsOnUp(functionList);
        }
    },
    {
        "keys"          : "down",
        "on_keydown"    : function() {
            functionsOnDown(functionList);
        }
    },
    {
        "keys"          : "enter",
        "on_keydown"    : function() {
            window.location = selectedFunction.href;
        }
    }, 
    {
        "keys"          : "esc",
        "on_keydown"    : function() {
            $("#function-name-input").blur();
        }
    },
]);

var selectedType = null;
var typeSearchListener = new window.keypress.Listener();
typeSearchListener.register_many([
    {
        "keys"          : "up",
        "on_keydown"    : function() {
            // functionsOnUp(functionList);
        }
    },
    {
        "keys"          : "down",
        "on_keydown"    : function() {
            // functionsOnDown(functionList);
        }
    },
    {
        "keys"          : "enter",
        "on_keydown"    : function() {
            // window.location = selectedFunction.href;
        }
    }, 
    {
        "keys"          : "esc",
        "on_keydown"    : function() {
            $("#type-name-input").blur();
        }
    },
]);



// http://stackoverflow.com/a/1844577
var currentHash = window.location.hash;
var returning = false;
window.addEventListener("hashchange", function() {
    // If the user has activated a return instruction, then we want to go all the way back. By
    // calling history.back(), we'll set off an infinite recursive loop that will keep running until
    // the previous page is opened.
    if (returning) {
        history.back();
    }
    else {
        if (window.location.hash != currentHash) {
            currentHash = window.location.hash;
            if (currentHash) {
                updateActiveInstr(currentHash.substring(1));
            }
            // If currentHash is undefined, it means we've gone back past the "start" of the page. This
            // means we need to go back to the previous page.
            else {
                history.back();
            }
        }
    }
}, false);


$('#function-name-input')
    .bind("focus", function() { 
        globalListener.stop_listening();
        mainListener.stop_listening();
        typeSearchListener.stop_listening();
        functionSearchListener.listen();
    })
    .bind("blur", function() { 
        globalListener.listen(); 
        mainListener.listen();
        typeSearchListener.stop_listening();
        functionSearchListener.stop_listening();
    });

$('#type-name-input')
    .bind("focus", function() { 
        globalListener.stop_listening(); 
        mainListener.stop_listening();
        functionSearchListener.stop_listening();
        typeSearchListener.listen();
    })
    .bind("blur", function() { 
        globalListener.listen(); 
        mainListener.listen();
        functionSearchListener.stop_listening();
        typeSearchListener.stop_listening();
    });
