function my_enable(element, state) {
  var input = document.getElementById(element).getElementsByTagName("input");
  for(var i = 0; i < input.length; i++) {
    input[i].disabled = !state;
  }
}

$(document).ready(function() {
  my_enable("external", $("#use_external").checked());
  $("#use_external").click(function() {
    my_enable("external", this.checked);
  });
});
