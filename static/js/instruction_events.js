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

function updateActiveInstr(addr) {
  jumpTo(addr);
  updateAnalysis();
}

function instructionClicked(e, model) {
  if (model.assembly.in_iaca == true) {
    appendIacaBytes(e, model);
    return;
  }

  var $target = $(e.target);
  if ($target.parents('.address').length) {
    addressClicked(e, model);
    return;
  }
  // http://stackoverflow.com/questions/17084839/check-if-any-ancestor-has-a-class-using-jquery
  else if ($target.parents('.mnemonic').length) {
    mnemonicClicked(e, model);
    return;
  }
  else if ($target.parents('.op_str').length) {
    opStrClicked(e, model);
    return;
  }
  // Adding else isn't necessary, but it looked cleaner and more clear to me.
  else {
    var addr = parseInt(model.i.address);
    showAnalysis();
    updateActiveInstr(model.i.address);
  }
}


function addressClicked(event, model) {

}

function opStrClicked(event, model) {
  if (model.i['jump-table']) {
    showJumptable();
  }
  else if (model.i['internal-jump'] && model.i.jumpTo) {
    internalJump(model.i.jumpTo[0]);
    get_stack_info(parseInt(model.i.jumpTo[0]));
  }
}

function mnemonicClicked(event, model) {
  showAnalysis();
  showFullDescription(model.i.docfile);
  tabMnemonicDescClicked(event, model);
}


/*********************************************/

function internalJump(address) {
  window.location.hash = assembly.active_instruction;
  updateActiveInstr(address);
  window.location.hash = assembly.active_instruction;
}

function scrollToJump(jumpToAddr) {
  var jumpToDiv = document.getElementById(jumpToAddr);
  // scroll to row
  $('#function-disasm').animate({
    scrollTop: jumpToDiv.offsetTop - $("#function-disasm").height()/2
  }, 100); 
}

function jumpTo(jumpToAddr) {
  // reset instruction highlighting
  $(".instruc-selected").removeClass("instruc-selected");

  scrollToJump(jumpToAddr);

  // add back highlighting
  var jumpToDiv = document.getElementById(jumpToAddr);
  jumpToDiv.classList.add("instruc-selected");
  assembly.active_instruction = jumpToAddr;
  // The way I see it, after jumping to an instruction and making it the active instruction, its
  // jump arrows should be highlighted as well. 
  highlightJumpArrows(assembly.jumps, jumpToAddr);
}

// append instruction objects to analysis.iaca_bytes
function appendIacaBytes(e, model) {
  var instruc = e.currentTarget;
  var bgColor = 'rgb(200,230,201)'; // keep consistent with scss

  // first instruction added
  if (analysis.iaca_bytes.length == 0) {
    instruc.style.backgroundColor = bgColor;
    analysis.iaca_bytes.push(model.i);
    if (model.i['internal-jump'] && model.i.jumpTo) {
      handleIacaJumpTo(model.i.jumpTo[0], bgColor);
    }
    return;
  }

  // append everything between the last thing clicked and this thing clicked
  var this_index = model.i.index;
  var last_index = analysis.iaca_bytes[analysis.iaca_bytes.length - 1].index;
  for (var j = last_index + 1; j <= this_index; j++) {
    var instruc_obj = assembly.contents[j];
    var instruc_element = document.getElementById(instruc_obj.address);
    instruc_element.style.backgroundColor = bgColor;
    analysis.iaca_bytes.push(instruc_obj);
  }

  // if you clicked a jump, also add the jumpTo instruction
  if (this_index > last_index && model.i['internal-jump'] && model.i.jumpTo) {
    handleIacaJumpTo(model.i.jumpTo[0], bgColor)
  }

}

// only called in appendIacaBytes; handle scrolling and bg highlighting of jumpTo instruc
function handleIacaJumpTo(targetAddr, bgColor) {
  scrollToJump(targetAddr);
  var jumpToObj = assembly.contents.filter(function(i) {
    return i.address == targetAddr;
  })[0];

  document.getElementById(jumpToObj.address).style.backgroundColor = bgColor;
  analysis.iaca_bytes.push(jumpToObj);
}



