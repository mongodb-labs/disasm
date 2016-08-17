function functionsOnUp(functionList) {
  if (!selectedFunction) { return; }
  var prev = selectedFunction.previousSibling;
  if (prev && $(prev).hasClass('function')) {
      $(selectedFunction).removeClass('selected');
      $(prev).addClass('selected');
      selectedFunction = prev;
  }

  // If the selected element is off-screen, scroll s.t. the selected element is at the 
  // to of the function list.
  var selectedTop = selectedFunction.getBoundingClientRect().top;
  var selectedBot = selectedFunction.getBoundingClientRect().bottom;
  var functionsTop = functionList.getBoundingClientRect().top;
  var functionsBot = functionList.getBoundingClientRect().bottom;
  if (selectedTop < functionsTop || selectedBot > functionsBot) {
      functionList.scrollTop += selectedTop - functionsTop;
  }
}

function functionsOnDown(functionList) {
  if (!selectedFunction) { return; }
  var next = selectedFunction.nextSibling;
  if (next && $(next).hasClass('function')) {
      $(selectedFunction).removeClass('selected');
      $(next).addClass('selected');
      selectedFunction = next;
  }
  // If the selected element is off-screen, scroll s.t. the selected element is at the 
  // bottom of the function list.
  var selectedTop = selectedFunction.getBoundingClientRect().top;
  var selectedBot = selectedFunction.getBoundingClientRect().bottom;
  var functionsTop = functionList.getBoundingClientRect().top;
  var functionsBot = functionList.getBoundingClientRect().bottom;
  if (selectedBot > functionsBot || selectedTop < functionsTop) {
      functionList.scrollTop += selectedBot - functionsBot;
  }
}