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

var URL_SOURCE_CODE = "/source_code_from_path";
var URL_IACA ='/iaca';

var analysis = {
  stack_info: [],
  source_code: {},
  iaca_bytes: []
};

var analysis_ctrl = {
  filepathClicked: filepathClicked,
  tabStackInfoClicked: tabStackInfoClicked,
  tabMnemonicDescClicked: tabMnemonicDescClicked,
  tabIacaClicked: tabIacaClicked,
  startIaca: startIaca,
  runIaca: runIaca,
  clearIaca: clearIaca
};

// The current call stack being displayed in the analysis tab
var activeStack = null;
// The index of the filepath currently selected in the call stack
var activeStackIndex = null;

rivets.bind($("#function-analysis"), 
  {analysis: analysis, ctrl: analysis_ctrl}
);

// Update the information in the analysis menu based on the currently selected instruction
function updateAnalysis() {
  get_stack_info(parseInt(assembly.active_instruction));
  var selectedInstruction = document.getElementById(assembly.active_instruction);
  var model = assembly.contents[selectedInstruction.getAttribute('data-index')];
  showFullDescription(model.docfile);
}

// Update the stack information in the Stack Info tab of the analysis menu
function get_stack_info(addr) {
  // info from DIE
  $.ajax({
    type: "GET",
    url: URL_DIE_INFO + "?address=" + addr
  })
  .done(function(data) {
    if (data == null || data[0] == null) {
      analysis.stack_info = [["No stack info for this instruction", ""]];
    }
    else {
      analysis.stack_info = data;
    }

    var stackIndex;
    if (activeStack && activeStackIndex) {
      // Find the first filepath in [0, activeStackIndex] that doesn't match the active stack.
      for (stackIndex = 0; stackIndex <= activeStackIndex; stackIndex++) {
        var activeFilepath = activeStack[stackIndex];
        var potentialFilepath = analysis.stack_info[stackIndex];
        if (!arrayEquals(activeFilepath, potentialFilepath)) {
          break;
        }
      }
      // We want the index to be the one before the first failed match.
      // If all matches failed (stackIndex == 0), then settle for index 0.
      stackIndex = stackIndex == 0 ? 0 : stackIndex-1;
    }
    else {
      // default to selecting first filepath.
      stackIndex = 0;
    }
    var frame = document.getElementsByClassName("stack-info-frame")[stackIndex];
    _filepathClicked(
      frame,
      stackIndex,
      analysis.stack_info[stackIndex][0], 
      analysis.stack_info[stackIndex][1]);
  });
}

function arrayEquals(a, b) {
  if (!a && !b) {
    return true;
  }
  if (!a || !b) {
    return false;
  }
  if (a.length != b.length) {
    return false;
  }
  for (var i = 0; i < a.length; i++) {
    if (a[i] !== b[i])
      return false;
  }
  return true;
}

/********** tab click functions **********/
function _tabClicked(classname) {
  $(".tab-content").hide();
  $(".tab-content" + classname).show();

  $(".tab").removeClass('active');
  $(".tab" + classname).addClass("active");
}

function tabStackInfoClicked(event, model) {
  assembly.in_iaca = false;
  _tabClicked(".tab-stack-info");
}

function tabMnemonicDescClicked(event, model) {
  assembly.in_iaca = false;
  _tabClicked(".tab-mnemonic-desc");
}

function tabIacaClicked(event, model) {
  if (analysis.iaca_bytes && analysis.iaca_bytes.length > 0) {
    assembly.in_iaca = true;
  }
  _tabClicked(".tab-iaca"); 
}
/********** end tab click functions **********/

// display functions: show and hide analysis panel
var fullHeight = "97vh";
var partialHeight = "50vh";
$("#function-analysis").hide(); // init hide.
var analysisVisible = false; // Whether or not the analysis menu is currently visible.

function showAnalysis() {
  analysisVisible = true;
  $("#function-analysis").show();
  $("#top-half").height(partialHeight);
}

function hideAnalysis() {
  analysisVisible = false;
  $("#function-analysis").hide();
  $("#top-half").height(fullHeight);
}

function showFullDescription(filename) {
  document.getElementById('full_desc').contentWindow.location.replace(filename);
  $('iframe#full-descript').contents().find("html").attr('font-size', '0.8em');
}


function filepathClicked(e, model) {
  _filepathClicked(e.currentTarget, model.index, model.frame[0], model.frame[1]);

}

// when a particular filepath is clicked, triggering an api call
// to get the source code
function _filepathClicked(element, index, src_path, lineno) {
  $(".file-selected").removeClass("file-selected");
  element.classList.add("file-selected");

  // Figure out which index in the stack this information is associated with.
  activeStack = analysis.stack_info;
  activeStackIndex = index;

  $.ajax({
    type: "POST",
    url: URL_SOURCE_CODE,
    data: {
      "src_path": src_path,
      "lineno": lineno
    }
  })
  .done(function(data) {
    if (data.hasOwnProperty("target")) {
      analysis.source_code = {
        "before": data['before'],
        "target": data['target'],
        "after": data['after']
      }

      // source code syntax highlighting
      $(".source-code pre").each(function(i, block) {
        hljs.highlightBlock(block);
      });

      // scroll to relevant line
      var offsetTop = $('.source-code .target').height() * lineno - $('.source-code').height()/2;
      $('.source-code').scrollTop(offsetTop);
    }
    // sent a filepath from root /
    else {
      analysis.source_code = {
        "before": "Sorry, cannot get source code from this path",
        "target": "",
        "after": ""
      };
    }
  })
  // should never happen, but exists as a placeholder
  .fail(function() { 
    analysis.source_code = {
      "before": "Sorry, cannot get source code from this path",
      "target": "",
      "after": ""
    }
  });
}

/************** IACA **************/
function startIaca(event, model) {
  $('.button.start-iaca').addClass('inactive')
  assembly.in_iaca = true;
}

function runIaca(event, model) {
  var string_of_bytes = ""
  analysis.iaca_bytes.forEach(function(i) {
    string_of_bytes += i.bytes;
  });

  getIaca(string_of_bytes);
}

function clearIaca() {
  $('.button.start-iaca').removeClass('inactive')
  $('.instruction').removeAttr('style');
  $('pre#iaca-contents').text("");
  assembly.in_iaca = false;
  analysis.iaca_bytes = []; 
}

function getIaca(string_of_bytes) {
  $.ajax({
    type: "POST",
    url: URL_IACA,
    data: {
      "string_of_bytes": string_of_bytes,
      "arch_type": $("select.architecture").val(),
      "analysis_type": $("select.analysis-type").val()
    }
  })
  .done(function(data) {
    if (data['error']) {
      if (data['error']['source'] && data['error']['source'] == 'subprocess') {
        var message = "Subprocess error: \n"
          + '\tDo you have the correct DYLD_LIBRARY_PATH for IACA in either your system environment'
          + ' variables, or in your config.py?'
      }
      else if (data['error']['source'] && data['error']['source'] == 'os') {
        var message = escapeHtml(data['error']['message'])
          + '\n' 
          + "\t(1) Do you have IACA installed? You can download it"
          + " <a href='https://software.intel.com/en-us/articles/intel-architecture-code-analyzer-download'>here</a>.\n"
          + "\t(2) Did you forget to update the IACA_PATH in your config.py,"
          + " or include the path to iaca in your $PATH?"
      }
      else {
        var message = escapeHtml(data['error']['message'])
          + '\n'
          + "\t Something went wong; please make sure you have IACA installed, and that the paths to"
          + " the executable and to the dyld libraries are correctly configured in your config.py."
      }
     
      $('pre#iaca-contents').html(message);
    }
    else if (data['contents']) {
      $('pre#iaca-contents').text(data['contents']);
    }
    
  });
}

function escapeHtml(str) {
  var div = document.createElement('div');
  div.appendChild(document.createTextNode(str));
  return div.innerHTML;
}
