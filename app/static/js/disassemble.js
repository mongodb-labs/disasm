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

/* INIT */
var URL_DIE_INFO = "/get_die_info";
var URL_FUNCTION_ASSEMBLY = '/get_function_assembly';
var URL_REG_CONTENTS = '/get_reg_contents';
var URL_GET_CSTRING = '/get_data_as_cstring';
var URL_JUMPTABLE = '/get_jumptable';
var URL_GET_TYPES = '/get_types';

// enums for register tracking/highlighting
var READS_REG = 0;
var WRITES_REG = 1;

var assembly = {
  contents : [], 
  func_name: "",
  filename: $("#function-metadata").attr('data-filename'),
  active_instruction: "",
  instructions_loading: false,
  in_iaca: false,
  highlight_read_reg: "",
  highlight_write_reg: "",
  jumps: [],
};

var assembly_ctrl = {
  instructionClicked: instructionClicked 
}

var type_ctrl = {
  typeData: [],
  typeClicked: typeClicked,
  typeDataQueried: [],
  selected_type: null,
  memberTypeClicked: memberTypeClicked,
  selectedTypeClicked: selectedTypeClicked,
  showTypeSearchResults: true,
};

var rivetsAnalysisView = rivets.bind($('#tab-type-info'),
  {type_ctrl: type_ctrl}
);

rivets.formatters.isEmptyStr = function(value) {
  return value == "";
}

var rivetsAssemblyView = rivets.bind($("#function-disasm"), 
  {assembly: assembly, ctrl: assembly_ctrl}
);

rivets.formatters.displayData = function(data) {
  return data != null && data != undefined;
}

assembly.instructions_loading = true;
get_function_assembly();

// Show the stack info by default.
tabStackInfoClicked();

// show or hide #functions
$("#function-name-input").focusin(function() {
  $(".input.row").addClass("focused");
}).focusout(function() {
  $(".input.row").removeClass("focused");
});

/* END INIT */

$(function() {
    $.contextMenu({
        selector: '.rip',
        items: {
            rip: {
                name: "Rip Relative",
                callback: function(key, opt) {
                  ripCallback(key, opt, '.rip-default');
                }
            },
            decoded: {
                name: "Resolved Address",
                callback: function(key, opt) {
                  ripCallback(key, opt, '.rip-resolved');

                }
            },
            value_ascii: {
                name: "Referenced Value (ASCII)",
                callback: function(key, opt) {
                  ripCallback(key, opt, '.rip-value-ascii');
                }
            },
            value_hex: {
              name: "Referenced Value (Hex)",
              callback: function(key, opt) {
                ripCallback(key, opt, '.rip-value-hex');
              }
            },
            value_signed: {
              name: "Signed Integer",
              items: {
                value_signed_8: {
                  name: "8-bit Signed Integer",
                  callback: function(key, opt) {
                    ripCallback(key, opt, '.rip-value-signed-8');
                  }
                },
                value_signed_16: {
                  name: "16-bit Signed Integer",
                  callback: function(key, opt) {
                    ripCallback(key, opt, '.rip-value-signed-16');
                  }
                },
                value_signed_32: {
                  name: "32-bit Signed Integer",
                  callback: function(key, opt) {
                    ripCallback(key, opt, '.rip-value-signed-32');
                  }
                },
                value_signed_64: {
                  name: "64-bit Signed Integer",
                  callback: function(key, opt) {
                    ripCallback(key, opt, '.rip-value-signed-64');
                  }
                },            
              }, 
            },
            value_unsigned: {
              name: "Unsigned Integer",
              items: {
                value_unsigned_8: {
                  name: "8-bit Unsigned Integer",
                  callback: function(key, opt) {
                    ripCallback(key, opt, '.rip-value-unsigned-8');
                  }
                },
                value_unsigned_16: {
                  name: "16-bit Unsigned Integer",
                  callback: function(key, opt) {
                    ripCallback(key, opt, '.rip-value-unsigned-16');
                  }
                },
                value_unsigned_32: {
                  name: "32-bit Unsigned Integer",
                  callback: function(key, opt) {
                    ripCallback(key, opt, '.rip-value-unsigned-32');
                  }
                },
                value_unsigned_64: {
                  name: "64-bit Unsigned Integer",
                  callback: function(key, opt) {
                    ripCallback(key, opt, '.rip-value-unsigned-64');
                  }
                },   
              },
            },
            value_hex: {
              name: "Hex Integer",
              items: {
                value_hex_8: {
                  name: "8-bit Hex Integer",
                  callback: function(key, opt) {
                    ripCallback(key, opt, '.rip-value-hex-8');
                  }
                },
                value_hex_16: {
                  name: "16-bit Hex Integer",
                  callback: function(key, opt) {
                    ripCallback(key, opt, '.rip-value-hex-16');
                  }
                },
                value_hex_32: {
                  name: "32-bit Hex Integer",
                  callback: function(key, opt) {
                    ripCallback(key, opt, '.rip-value-hex-32');
                  }
                },
                value_hex_64: {
                  name: "64-bit Hex Integer",
                  callback: function(key, opt) {
                    ripCallback(key, opt, '.rip-value-hex-64');
                  }
                },
              },
            },
            value_floating_point: {
              name: "Floating Point",
              items: {
                value_float: {
                  name: "Single-Precision Floating Point",
                  callback: function(key, opt) {
                    ripCallback(key, opt, '.rip-value-float');
                  }
                },
                value_double: {
                  name: "Double-Precision Floating Point",
                  callback: function(key, opt) {
                    ripCallback(key, opt, '.rip-value-double');
                  }
                },
              },
            },
            cstring: {
              name: "Referenced Value (cString)",
              callback: function(key, opt) {
                $(opt.$trigger.context).find('rip-value-cstring').html("Loading...");
                ripCallback(key, opt, '.rip-value-cstring');
                var cString;
                $.get(
                  URL_GET_CSTRING, 
                  {
                    file_offset: parseInt(opt.$trigger.context.getAttribute('value')),
                    filename: assembly.filename
                  }
                )
                .done(function(data) {
                  cString = data;
                })
                .fail(function() {
                  cString = "Unable to get cString from this value";
                  console.log("Failed");
                })
                .always(function() {
                  console.log(cString);
                  $(opt.$trigger.context).find('.rip-value-cstring')[0].innerHTML = cString;
                });
              }
            },
            symbol: {
              name: "Symbol",
              callback: function(key, opt) {
                ripCallback(key, opt, '.rip-symbol');
              },
              disabled: function(key, opt) {
                // We want to show this item iff the rip-symbol element exists
                console.log($(opt.$trigger.context).find('.rip-symbol').length);
                return $(opt.$trigger.context).find('.rip-symbol').length == 0;
              }
            }
        }
    });
});

function ripCallback(key, opt, classToShow) {
  var $rip = $(opt.$trigger.context);
  $rip.find("[class^='rip-']").attr("hidden", "hidden");
  $rip.find(classToShow).removeAttr("hidden");
}

// for arrows (jump highlighting)
var svg = d3.select('#function-disasm .jump-arrows')
  .append('svg:svg')
  .attr('width', '100%');

svg.append('svg:defs')
  // create arrowhead
  .append('svg:marker')
  .attr({
    'id': 'arrow',
    "viewBox": "0 -5 10 10",
    "refX": 8,
    "refY": 0,
    "markerWidth": 4,
    "markerHeight": 4,
    "orient": "auto",
    "fill": "gray",
  })
  .append('svg:path')
  .attr("d", "M0,-5L10,0L0,5");


// get assembly for given function, given as DOM element
function get_function_assembly() {
  // disassemble function
  var $metadata = $("#function-metadata");
  var st_value = $metadata.attr('data-st-value');
  request_params = {
    filename: assembly.filename,
    st_value: st_value,
    file_offset: $metadata.attr('data-file-offset'),
    size: $metadata.attr('data-size')
  }

  $.ajax({
    type: "GET",
    url: URL_FUNCTION_ASSEMBLY + '?' + $.param(request_params)
  })
  .done(function(data) {
    // Process each line of assembly
    assembly.data = data.map(function(i, index) {
      i.index = index;

      // Process address
      var _address = i.address
      i.address = "0x" + _address.toString(16);

      // Process mnemonic
      var _mnemonic = i.mnemonic;

      // Process op_str
      var _op_str = i.op_str;
      if (i['rip']) {
        var replacementStr =  "";
        replacementStr += '<span class="rip" value="' + i['rip-resolved'] + '">[';
        replacementStr += '<span class="rip-default">rip + ' + i['rip-offset'] + '</span>';
        replacementStr += '<span class="rip-resolved" hidden>' + i['rip-resolved'] + '</span>';
        replacementStr += '<span class="rip-value-ascii" hidden>"' + i['rip-value-ascii'] + '"</span>';
        replacementStr += '<span class="rip-value-hex" hidden>' + i['rip-value-hex'] + '</span>';
        replacementStr += '<span class="rip-value-signed-8" hidden>' + i['rip-value-signed-8'] + '</span>';
        replacementStr += '<span class="rip-value-signed-16" hidden>' + i['rip-value-signed-16'] + '</span>';
        replacementStr += '<span class="rip-value-signed-32" hidden>' + i['rip-value-signed-32'] + '</span>';
        replacementStr += '<span class="rip-value-signed-64" hidden>' + i['rip-value-signed-64'] + '</span>';
        replacementStr += '<span class="rip-value-unsigned-8" hidden>' + i['rip-value-unsigned-8'] + '</span>';
        replacementStr += '<span class="rip-value-unsigned-16" hidden>' + i['rip-value-unsigned-16'] + '</span>';
        replacementStr += '<span class="rip-value-unsigned-32" hidden>' + i['rip-value-unsigned-32'] + '</span>';
        replacementStr += '<span class="rip-value-unsigned-64" hidden>' + i['rip-value-unsigned-64'] + '</span>';
        replacementStr += '<span class="rip-value-hex-8" hidden>' + i['rip-value-hex-8'] + '</span>';
        replacementStr += '<span class="rip-value-hex-16" hidden>' + i['rip-value-hex-16'] + '</span>';
        replacementStr += '<span class="rip-value-hex-32" hidden>' + i['rip-value-hex-32'] + '</span>';
        replacementStr += '<span class="rip-value-hex-64" hidden>' + i['rip-value-hex-64'] + '</span>';
        replacementStr += '<span class="rip-value-float" hidden>' + i['rip-value-float'] + '</span>';
        replacementStr += '<span class="rip-value-double" hidden>' + i['rip-value-double'] + '</span>';
        replacementStr += '<span class="rip-value-cstring" hidden></span>';
        replacementStr += ']</span>';
        i.op_str = i.op_str.replace(/\[.*\]/, replacementStr);
      }
      else if (i['nop']) {
        i.op_str = i.size + " bytes";
      }
      else if (i['external-jump']) {
        var addr = i.op_str
        i.op_str = '<a href="disasm_function?';
        i.op_str += 'filename=' + assembly.filename;
        i.op_str += '&st_value=' + i['jump-function-address'];
        i.op_str += '&file_offset=' + i['jump-function-offset'];
        i.op_str += '&size=' + i['jump-function-size'];
        i.op_str += '&func_name=' + i['jump-function-name'];
        i.op_str += '">' + addr + '</a>';
      }

      if (i['comment']) {
        i.comment_html = '<span class="comment"> ; ' + i['comment'] + '</span>';
      }

      if (i['flags']) {
        if (i['flags']['W']) {
          i.has_flag_write = true 
          i['flags']['W'] = i['flags']['W'].join(" ")
        }
        if (i['flags']['R']) { 
          i.has_flag_read = true 
          i['flags']['R'] = i['flags']['R'].join(" ")
        }
      }

      // handle registers
      var regs_str = "";
      if (i['regs_write_implicit'] && i['regs_write_implicit'].length > 0) {
        var regs_write = removeFlagsRegs(i['regs_write_implicit']);
        if (regs_write.length > 0) {
          regs_str = "W: ";
          regs_str += "<span class='reg'>" + regs_write.join(' ') + "</span>";
        } 
      }

      if (i['regs_read_implicit'] && i['regs_read_implicit'].length > 0) {
        var regs_read = removeFlagsRegs(i['regs_read_implicit']);
        if (regs_read.length > 0) {
          if (regs_str.length > 0) {
            regs_str += ", R: ";
          }
          else if (regs_str.length == 0) {
            regs_str += " R: ";
          }
          regs_str += "<span class='reg'>" + regs_read.join(' ') + "</span>";
        } 
      }

      if (regs_str.length > 0) {
        regs_str = i['comment'] ? ', ' + regs_str : ' ; ' + regs_str;
        if (i.comment_html) {
          i.comment_html += "<span class='comment regs'>" + regs_str + "</span>";
        }
        else {
          i.comment_html = "<span class='comment regs'>" + regs_str + "</span>";
        } 
      }

      // Process etc.

      return i;
    });

    // clear loading icon
    assembly.instructions_loading = false;
    assembly.contents = data;

    if (window.location.hash) {
      // Set the page's hash and active instruction to be the id of the first instruction
      jumpTo(window.location.hash.substring(1));
      assembly.active_instruction = window.location.hash.substring(1);
    } else {
      // If we've navigated back to this page, then set the hash and active instruction to be the
      // instruction we were at before we left
      window.location.hash = assembly.contents[0].address;
      assembly.active_instruction = assembly.contents[0].address;
    }
      
    // Highlight the first instruction
    $(document.getElementById(assembly.active_instruction)).addClass('instruc-selected');

    // syntax highlighting
    $(".instructions span.row.instruction").each(function(i, block) {
      hljs.highlightBlock(block);
    });

    // load jump info
    handleJumpHighlighting();

    // Adds a "hex" or "twosCompDec64" class to all numbers
    wrapAllNumbers();

    // Adds a "reg" class to all registers
    wrapAllRegisters();

    // initialize tooltips
    $('.tip').tipr({
      'speed': 100
    });

    // load register content info
    $.ajax({
      type: "GET",
      url: URL_REG_CONTENTS + "?address=" + st_value + "&filename=" + assembly.filename
    }).done(function(data){
      handleRegisterContent(data, st_value);
      console.log(data)
    });

    // load type data.
    var typeData;
    $.get(URL_GET_TYPES, {
      filename: assembly.filename,
      addr: parseInt(assembly.contents[0]['address'], 16)
    })
    .done(function(data) {
      console.log("Done loading type data.");
      typeData = data;
    })
    .fail(function() {
      console.log("Unable to load type data.");
      typeData = [];
    })
    .always(function() {
      type_ctrl.typeDataList = rivets.formatters.typeDataToList(typeData);
      type_ctrl.typeData = typeData;
      type_ctrl.typeDataQueried = [];
      
      // For some FASCINATING, unknown reason, despite defaulting to true, the related data will
      // appear as though showTypeSearchResults were false. This can be fixed by setting it to false
      // then back to true.
      type_ctrl.showTypeSearchResults = false;
      type_ctrl.showTypeSearchResults = true;
    });

    // preload DIE info from server
    $.ajax({
      type: "GET",
      url: URL_DIE_INFO + "?address=" + st_value + "&filename=" + assembly.filename
    });

  })
  .fail(function(data) {
    console.log("Request failed");
  });

  return false;
}


function removeFlagsRegs(reg_array) {
  var flags_index = reg_array.indexOf('rflags');
  if (flags_index > -1) {
    reg_array.splice(flags_index, 1);
  }
  return reg_array;
}


// wrap numbers for base changes etc.
function wrapAllNumbers() {
  $('.hljs-number').each(function(index, elem) {
    wrapNumbersInElem(elem);
  });
}

function wrapNumbersInElem(elem) {
  var charOne = elem.innerHTML.charAt(0);
  var charTwo = elem.innerHTML.charAt(1);
  if (charOne == '0' && charTwo == 'x') {
    // elem.className += ' hex';
    elem.setAttribute('value', 'hex');
  }
  else if (charOne >= '0' && charTwo <= '9') {
    elem.setAttribute('value', 'twosCompDec64');
  }
  else {
    console.log("Unknown data type:");
    console.log(elem)  }
}

// wrap registers for register tracking
function wrapAllRegisters() {
  $(".instruction .op_str").each(function(index, el) {
    var instruc = assembly.contents[index];
    var instruc_regs = instruc.regs_write_explicit
      .concat(instruc.regs_write_implicit, instruc.regs_read_implicit, instruc.regs_read_explicit);
    
    // wrap normal registers and ptr registers
    var ops = el.getElementsByClassName('hljs-built_in');
    for (var i = 0; i < ops.length; i++) {
      // register
      if (instruc_regs.indexOf(ops[i].innerText) >= 0) {
        ops[i].classList.add("reg");
      }
      // ptr if it's not rip relative; also add the reg
      if (ops[i].innerText == 'ptr' && !textInHtmlCollection(ops, 'rip')) {
        ops[i].classList.add("reg");
        var reg = assembly.contents[index].ptr;
        reg = reg.filter(val => val != "").join(" ");
        ops[i].setAttribute('id', reg);
      }
    }
  });
}

function textInHtmlCollection(collection, text) {
  for (var i = 0; i < collection.length; i++) {
    if (collection[i].innerText == text) {
      return true;
    }
  }
  return false;
}
