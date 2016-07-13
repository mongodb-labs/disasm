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

 function addressClicked(event, model) {

 }

 function opStrClicked(event, model) {
 	if (model.i.is_jump) {
 		jumpTo(model, model.i.jumpTo);
 	}
 }

 function mnemonicClicked(event, model) {
 	
 }

/*********************************************/

 function jumpTo(model, jumpTo) {
 	var addr = jumpTo[0];
 	var jumpToDiv = document.getElementById(addr);

 	// reset instruction highlighting
	$(".instruc-selected").removeClass("instruc-selected");

	// scroll to row
	$('#function-disasm').animate({
		scrollTop: jumpToDiv.offsetTop
	}, 'fast');

	// clear any selected filepaths and source code
	hideAnalysis();
	$(".file-selected").removeClass("file-selected");
	analysis.source_code = {};

	// add back highlighting
	jumpToDiv.classList.add("instruc-selected");
 }