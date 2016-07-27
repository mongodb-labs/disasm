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

 /*************** For register canonicalization ***************/
var register_names_all = [
  ['al', 'ah', 'ax', 'eax', 'rax'],
  ['bl', 'bh', 'bx', 'ebx', 'rbx'],
  ['cl', 'ch', 'cx', 'ecx', 'rcx'],
  ['dl', 'dh', 'dx', 'edx', 'rdx'],
  ['r8b', 'r8w', 'r8d', 'r8'],
  ['r9b', 'r9w', 'r9d', 'r9'],
  ['r10b', 'r10w', 'r10d', 'r10'],
  ['r11b', 'r11w', 'r11d', 'r11'],
  ['r12b', 'r12w', 'r12d', 'r12'],
  ['r13b', 'r13w', 'r13d', 'r13'],
  ['r14b', 'r14w', 'r14d', 'r14'],
  ['r15b', 'r15w', 'r15d', 'r15'],
  ['bpl', 'bp', 'ebp', 'rbp'],
  ['sil', 'si', 'esi', 'rsi'],
  ['dil', 'di', 'edi', 'rdi'],
  ['spl', 'sp', 'esp', 'rsp']];
var register_names = {};
register_names_all.forEach(function(names, index) {
  names.forEach(function(name) {
    register_names[name] = names;
  })
});
for (var i = 0; i <= 15; i++) {
  var names = ['zmm'+i, 'ymm'+i, 'zmm'+i];
  names.forEach(function(name) {
    register_names[name] = names;
  });
}
/* END INIT */

// are the two given registers equal, canonically?
function regsEq(regA, regB) {
  var regsA = register_names[regA.toLowerCase()];
  var regsB = register_names[regB.toLowerCase()];
  if (!regA || !regsB) {
    return true;
  }
  else {
    return regsA.reduce(function(prev, cur, index) {
      return prev && (cur == regsB[index]);
    }, false);
  }
}

$(function() {
    $.contextMenu({
    selector: '.reg',
    items: {
      reads_from: {
        name: "Show reads",
        callback: function(key, opt) {
          var target_reg = $(this)[0].innerText;
          if (target_reg == 'ptr') {
            target_reg = $(this).attr('id');
          }

          var instructs = regsCallback(key, opt, target_reg, READS_REG);
          
          $(".show-read").removeClass("show-read");
          assembly.highlight_read_reg = target_reg;
          instructs.forEach(function(instr) {
            $('#' + instr.address).addClass('show-read');
          });
        }
      },
      writes_to: {
        name: "Show writes",
        callback: function(key, opt) {
          var target_reg = $(this)[0].innerText;
          if (target_reg == 'ptr') {
            target_reg = $(this).attr('id');
          }

          var instructs = regsCallback(key, opt, target_reg, WRITES_REG);
          
          $(".show-write").removeClass("show-write");
          assembly.highlight_write_reg = target_reg;
          instructs.forEach(function(instr) {
            $('#' + instr.address).addClass('show-write');
          }); 
        }
      },
      clear_all: {
        name: "Clear highlighting",
        callback: function(key, opt) {
          clearReadHighlighting();
          clearWriteHighlighting();
        }
      }
    }
  });
})

// invoked by context menu;
// highlight the relevant instructions that write to or read from target register
function regsCallback(key, opt, target_reg, readsOrWrites) {
  // canonicalize register names
  var target_reg = target_reg.toLowerCase();
  if (register_names[target_reg]) {
    var target_regs = register_names[target_reg];
  }
  else {
    var target_regs = [target_reg];
  }

  if (readsOrWrites == READS_REG) {
    var mode = "regs_read";
  }
  else if (readsOrWrites == WRITES_REG) {
    var mode = "regs_write";
  }
  else return undefined;
  
  // filter out all instructions that don't include the register in either
  // its implicit or explicit actions
  var instrucs = assembly.contents.filter(function(instr, index) {
    var explicit = instr[mode + "_explicit"].reduce(function(prev, reg) {
      return prev || (target_regs.indexOf(reg) >= 0);
    }, false);
    var implicit = instr[mode + "_implicit"].reduce(function(prev, reg) {
      return prev || (target_regs.indexOf(reg) >= 0);
    }, false);
    return explicit || implicit;
  });
  return instrucs;
}

// clear registers read highlighting
function clearReadHighlighting() {
  $(".show-read").removeClass("show-read");
  assembly.highlight_read_reg = ""
}

// clear registers write highlighting
function clearWriteHighlighting() {
  $(".show-write").removeClass("show-write");
  assembly.highlight_write_reg = "";
}

// given register content data, update assembly.contents accordingly
function handleRegisterContent(data) {
  assembly.contents.forEach(function(instr, index) {
    // filter out duplicates and include canonical names
    var instr_regs = instr['regs_read_explicit'].concat(instr['regs_write_explicit'])
      .map(function(reg) {
        return register_names[reg]
      });
    instr_regs = [].concat.apply([], instr_regs);
    instr_regs = instr_regs.filter(function(reg, pos, arr) {
        return arr.indexOf(reg) == pos;
      });

    instr_regs.forEach(function(instr_reg) {
      if (data[instr_reg]) {
        data[instr_reg].forEach(function(variable_loc) {
          var instr_in_loc = parseInt(variable_loc.start) <= parseInt(instr.address) 
            && parseInt(instr.address) < parseInt(variable_loc.end)
          // display size only if necessary
          if (variable_loc.size) {
            size = "(" + variable_loc.size + ")";
          }
          else {
            size = ""
          }
          // is the instruction in the variable's range?
          var comment_content_base = variable_loc.name + "=" + variable_loc.value + size;
          if (instr_in_loc && instr.comment_html) {
            var comment_content = "<span class='comment'>, " + comment_content_base + "</span>";
            $("#" + instr.address).find(".comments").append(comment_content);
            assembly.contents[index].comment_html += comment_content
          }
          else if (instr_in_loc && !instr.comment_html) {
            var comment_content = "<span class='comment'> ; " + comment_content_base + "</span>";
            $("#" + instr.address).find(".comments").append(comment_content);
            assembly.contents[index].comment_html = comment_content
          }
        });
      }
    });
  });
}