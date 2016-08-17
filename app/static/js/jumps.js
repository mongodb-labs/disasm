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

var jumptable = {
  active_jumptable: [],
  show_jumptable: false,
  switch_reg: "",
  active_jump_from: "",
  jump_to: function(event, model) {
    if (!assembly.in_iaca) {
      updateActiveInstr(model.jump.address);
    }
    else if (assembly.in_iaca) {
      handleIacaJumpTo(model.jump.address);
      hideJumptable();
    }
  },
}

var rivetsJumpView = rivets.bind($("#jumptable-info"),
  { jt: jumptable }
);

/************/

// display jump arrows
function handleJumpHighlighting() {
  // load into assembly.contents
  assembly.contents = assembly.contents.map(function(line, i) {
    if (line['internal-jump']) {
      line['jumpTo'] = [line['jump-address']]; // arr to future-proof
    }
    if (line['jump-table']) {
      handleJumpTable(i);
    }
    return line
  });

  drawJumpArrows();
  attachInstructionHandlers(assembly.jumps);
}

// highlight the mouseover-ed or clicked jump
function attachInstructionHandlers() {
  var jumps = assembly.jumps;
  $(".row.instruction").on("mouseenter", function(event) {
    var instruc = event.currentTarget;
    highlightJumpArrows(instruc.id);
  });
}

function drawJumpArrows() {
  // build array of { from: <addr>, to: <addr> }
  assembly.jumps = [];
  assembly.contents.map(function(line) {
    if (line['internal-jump']) {
      line['jumpTo'].forEach(function(jumpAddress) {
        var jumpToDiv = document.getElementById(jumpAddress);
        var jumpFromDiv = document.getElementById(line.address);
        if (jumpToDiv) {
          assembly.jumps.push({
            "from": line.address,
            "fromY": jumpFromDiv.offsetTop + (jumpFromDiv.clientHeight/2.0),
            "to": jumpAddress,
            "toY": jumpToDiv.offsetTop + (jumpToDiv.clientHeight/2.0)
          });
        }
      });
    }
  });

  // actually draw arrows
  var instructions = document.getElementsByClassName('instructions')[0];
  var svg_height = instructions.clientHeight;
  var svg_width = document.getElementsByClassName('jump-arrows')[0].clientWidth;
  

  // clear if anything there
  svg.selectAll('g').remove();
  svg.attr('height', svg_height);
  svg.append('svg:g')
    .attr('transform', function(jump, i) {
      return 'scale(-1, 1) translate(-' + svg_width + ', 0)';
    })
    .selectAll('path')
    .data(assembly.jumps)
    .enter().append('svg:path')
    .attr('d', function(jump, i) {
      var x = 5;
      var ext = (svg_width - x - 5) * (Math.abs(jump.fromY - jump.toY)/svg_height);
      ext = Math.max(5, ext);

      var command = "M" + x + " " + jump.fromY + " " +
        "h " + (x+ext) + " " +      // diff horizontally
        "V " + jump.toY + " " +     // vertical location
        "h " + (-(x+ext)) + " "     // diff horizontally
      return command;
    })
    .attr('marker-end', "url(#arrow)")
    .attr('opacity', 0.3)
    .attr('stroke', "gray");
    
}

// I wanted to call highlightJumpArrows elsewhere, so I moved jumps to the assembly object, since
// A) it seemed more appropriate since the jumps don't change within the scope of this function's
// assembly, and B) that way I could call it from elsewhere in the code
function highlightJumpArrows(instruc_id) {
  var jumps = assembly.jumps;
  var instr_active = assembly.active_instruction;

  // highlight if has jump
  svg.selectAll('g path')
    .data(jumps)
    .attr('opacity', function(jump, b) {
      if (jump['from'] == instr_active || jump['to'] == instr_active) {
        return 1;
      }
      else if (jump['from'] == instruc_id || jump['to'] == instruc_id) {
        return 1;
      }
      else {
        return 0.3;
      }
    })
    .attr('stroke', function(jump, b) {
      if (jump['from'] == instr_active || jump['to'] == instr_active) {
        return "rgb(3,169,244)";
      }
      if (jump['from'] == instruc_id || jump['to'] == instruc_id) {
        return "rgb(41,182,246)";
      }
      else {
        return "gray";
      }
    });
}

function handleJumpTable(i) {
  var input_data = assembly.contents.slice(0, i+1).map(function(instr) {
    return  {
      "address": instr.address,
      "bytes": instr.bytes,
      "index": instr.index,
      "mnemonic": instr.mnemonic,
      "ptr": instr.ptr,
      "ptr_size": instr["ptr_size"],
      "ptr_address": instr["rip-resolved"],
      "regs_read_explicit": instr.regs_read_explicit,
      "regs_write_explicit": instr.regs_write_explicit,
      "regs_read_implicit": instr.regs_read_implicit,
      "regs_write_implicit": instr.regs_write_implicit,
    }
  });

  $.ajax({
    type: "POST",
    url: URL_JUMPTABLE,
    data: {
      "filename": assembly.filename,
      "function_start": assembly.contents[0]["address"],
      "function_end": assembly.contents[assembly.contents.length - 1]["address"],
      "data": JSON.stringify(input_data)
    },
  }).done(function(data) {
    if (!data["jumptable"]) {
      return;
    }
    // set bg color of relevant op_str
    var $jumpFromRegDiv = $("#" + assembly.contents[i].address);
    $jumpFromRegDiv.find(".op_str-text").addClass("jt-op_str-text");
    if (assembly.contents[i]["comment_html"]) {
      var comment_body = " , click for jump table";
    }
    else {
      var comment_body = " ; click for jump table";
    }
    var comment_content = "<span class='comment'>" + comment_body + "</span>";
    $jumpFromRegDiv.find(".comments").append(comment_content);

    // load data into assembly and draw the arrows
    var jt = data["jumptable"];
    assembly.contents[i]["internal-jump"] = true;
    assembly.contents[i]["jumpTo"] = jt.map(function(jump) {
      return jump["address"];
    });
    drawJumpArrows();

    // load jumptable object
    jumptable.active_jumptable = jt;
    jumptable.active_jump_from = assembly.contents[i].address;

    // load register that is "switched" upon
    if (data['switch_reg']) {
      jumptable.switch_reg = data['switch_reg'];
    }
    else {
      jumptable.switch_reg = "indexes";
    }
  });
}

function showJumptable() {
  if (jumptable.show_jumptable) {
    // clear animation and reset after a (short) timeout
    $("#jumptable-info").css({
      "-webkit-animation": "none",
      "animation": "none",
    });
    setTimeout(function() {
      $("#jumptable-info").css({
        "-webkit-animation": "",
        "animation": "",
      });
    }, 10);
  } 
  jumptable.show_jumptable = true;
}

function hideJumptable() {
  jumptable.show_jumptable = false;
}

// adjust jump arrows when window size changes
window.addEventListener("resize", function() {
  var curWidth = window.innerWidth;
  setTimeout(function() {
    if (curWidth == window.innerWidth) {
      drawJumpArrows();
    }    
  }, 150);
});





