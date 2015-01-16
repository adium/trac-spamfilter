function ToggleSelect()
{
  var box = document.getElementById("selallbutton");
  var state = box.checked;
  var checkboxes = document.forms[toggleform].elements["sel"];
  var num = checkboxes.length;
  if(!num)
    checkboxes.checked = state;
  else
    for(var i = 0; i < num; ++i)
      checkboxes[i].checked = state;
}

$(document).ready(function() {
  if(document.forms[toggleform].elements["sel"])
  {
    document.getElementById("selallfield").innerHTML =
    "<input type=\"checkbox\" id=\"selallbutton\" onclick=\"ToggleSelect()\"/>";
  }
});
