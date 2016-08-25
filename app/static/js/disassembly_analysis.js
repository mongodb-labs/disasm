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
  tabTypeInfoClicked: tabTypeInfoClicked,
  startIaca: startIaca,
  runIaca: runIaca,
  clearIaca: clearIaca,
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
  var active_instr = assembly.active_instruction;
  setTimeout(function() {
    if (active_instr != assembly.active_instruction) {
      return;
    }
    get_stack_info(parseInt(assembly.active_instruction));
    var selectedInstruction = document.getElementById(assembly.active_instruction);
    var model = assembly.contents[selectedInstruction.getAttribute('data-index')];
    showFullDescription(model.docfile);
  }, 100);
}

// Update the stack information in the Stack Info tab of the analysis menu
function get_stack_info(addr) {
  // info from DIE
  filename = assembly.filename;
  $.ajax({
    type: "GET",
    url: URL_DIE_INFO + "?address=" + addr + "&filename=" + filename
  })
  .done(function(data) {
    if (data == null || data[0] == null) {
      analysis.stack_info = 
      [["No stack info for this instruction. This executable may not have a .debug_info section", ""]];
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
  _tabClicked(".tab-stack-info");
}

function tabMnemonicDescClicked(event, model) {
  _tabClicked(".tab-mnemonic-desc");
}

function tabIacaClicked(event, model) {
  if (analysis.iaca_bytes && analysis.iaca_bytes.length > 0) {
    assembly.in_iaca = true;
  }
  _tabClicked(".tab-iaca"); 
}

function tabTypeInfoClicked(event, model) {
  _tabClicked(".tab-type-info");
}
/********** end tab click functions **********/

// display functions: show and hide analysis panel
var fullHeight = "calc(97vh - 100px)"; // 100px header
var partialHeight = "39vh";
$("#function-analysis").hide(); // init hide
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

var tabStr = String.fromCharCode(160) + String.fromCharCode(160) + String.fromCharCode(160) + String.fromCharCode(160);
rivets.formatters.formatIndentation = function(depth) {
  indentationStr = "";

  for (var i = 0; i < depth; i++)
    indentationStr += tabStr;
  return indentationStr;
}

function _selectedTypeClicked(typeName) {
  var typeData = type_ctrl.typeData[typeName];
  if (typeData) {
    type_ctrl.selected_type = typeData;
    type_ctrl.showTypeSearchResults = false;
  }
  else
    return;  
}

function memberTypeClicked(e, model) {
  var typeName = model.member.type;
  _selectedTypeClicked(typeName);
}

function selectedTypeClicked(e, model) {
  var typeName = model.type_ctrl.selected_type.subtype;
  _selectedTypeClicked(typeName);
}

// When the type name input is changed, clear the current list of matching type names, and replace
// it with the new request.
var prevQuery = "";
$('#type-name-input').on('keyup', function() {
  query = this.value.toLowerCase();
  if (prevQuery == query) {
    return;
  }
  prevQuery = query;
  type_ctrl.queryString = query;
  type_ctrl.queryResults = [];

  // First empty the list.
  dataTypesEl = document.getElementById('data-types');
  while (dataTypesEl.firstChild) {
    dataTypesEl.removeChild(dataTypesEl.firstChild);
  }

  // Iterate through the list of types to find matches.
  for (var typeName in type_ctrl.typeData) {
    if (typeName.toLowerCase().indexOf(query) != -1) {
      type_ctrl.queryResults.push(typeName);

      // Finally, add these matches to the list.
      var newRes = document.createElement('a');
      newRes.setAttribute('data-name', typeName);
      newRes.className = 'type';
        var innerSpan = document.createElement('span');
        innerSpan.innerText = typeName;
      newRes.appendChild(innerSpan);
      $(newRes).click(function(event) {
        var typeName = event.delegateTarget.getAttribute('data-name');
        _selectedTypeClicked(typeName);
      });
      dataTypesEl.appendChild(newRes);
    }
  }
  dataTypesEl.firstChild.className += " selected";
  selectedType = dataTypesEl.firstChild;
  type_ctrl.showTypeSearchResults = true;
});

rivets.formatters.getQueryResults = function(query) {
  var queryResults = [];
  // Iterate through the list of types to find matches.
  for (var typeName in type_ctrl.typeData) {
    if (typeName.toLowerCase().indexOf(query) != -1) {
      queryResults.push(type_ctrl.typeData[typeName]);
    }
  }
  return queryResults;
};


rivets.formatters.endOfLine = function(member) {
  return !member.expandable && !member.collapsable;
}

function expandMember(event, model) {
  var members = type_ctrl.selected_type.members;
  var thisDepth = model.member.depth;
  var i = model.index + 1;
  while (members[i].depth > thisDepth) {
    if (members[i].depth == thisDepth + 1) {
      members[i].expanded = true;
    }
    i += 1;
  members[model.index].expandable = false;
  members[model.index].collapsable = true;
  }
}

function collapseMember(event, model) {
  var members = type_ctrl.selected_type.members;
  var thisDepth = model.member.depth;
  var i = model.index + 1;
  while (members[i].depth > thisDepth) {
    members[i].expanded = false;
    if (members[i].collapsable) {
      members[i].expandable = true;
      members[i].collapsable = false;
    }
    i += 1;
    members[model.index].expandable = true;
    members[model.index].collapsable = false;
  }  
}

// handlers for collapsing/expanding all
$(".collapse-all").on("click", function() {
  type_ctrl.selected_type.members.forEach(function(member) {
    if (member.collapsable) {
      member.collapsable = false;
      member.expandable = true;
    }
    member.expanded = member.depth == 0;
  });
});

$(".expand-all").on("click", function() {
  type_ctrl.selected_type.members.forEach(function(member) {
    if (member.expandable) {
      member.collapsable = true;
      member.expandable = false;
    }    
    member.expanded = true;
  });
});





