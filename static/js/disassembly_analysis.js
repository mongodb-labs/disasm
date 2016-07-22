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

rivets.bind($("#function-analysis"), 
  {analysis: analysis, ctrl: analysis_ctrl}
);

// get stack info from address
function get_stack_info(addr) {
  $(".tab-content").hide();

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
    tabStackInfoClicked();

    // default to selecting first frame
    var first_frame = document.getElementsByClassName("stack-info-frame")[0];
    _filepathClicked(first_frame, analysis.stack_info[0][0], analysis.stack_info[0][1]);
  });
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
$("#function-analysis").hide(); // init hide
function showAnalysis() {
  $("#function-analysis").show();
  $("#top-half").height(partialHeight);
}

function hideAnalysis() {
  $(".instruc-selected").removeClass("instruc-selected");
  $("#function-analysis").hide();
  $("#top-half").height(fullHeight);
  assembly.active_instruction = "";
}

function showFullDescription(e, filename) {
  $('#full_desc').attr('src', filename);
  $('iframe#full-descript').contents().find("html").attr('font-size', '0.8em');
}


function filepathClicked(e, model) {
  _filepathClicked(e.currentTarget, model.frame[0], model.frame[1])
}

// when a particular filepath is clicked, triggering an api call
// to get the source code
function _filepathClicked(element, src_path, lineno) {
  $(".file-selected").removeClass("file-selected");
  element.classList.add("file-selected");

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
