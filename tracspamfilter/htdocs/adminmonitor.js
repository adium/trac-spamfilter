function ToggleSelectPerfect(all, no, name)
{
  var bayes = bayestext.replace("%%", "%");
  var box = document.getElementById(name);
  var state = box.checked;
  var table = document.getElementById("spamtable");
  var respam = new RegExp(bayes.replace("%s", "9\\d\\.\\d\\d"))
  var reham = new RegExp(bayes.replace("%s", "\\d\\.\\d\\d"))

  var lines = table.getElementsByTagName('tr');
  for(var i = 0; i < lines.length; i += 2)
  {
    var checkbox = lines[i].getElementsByTagName('input')[0];
    var sstate = lines[i].className.indexOf("rejected");
    var html = lines[i+1].innerHTML;
    if(all && sstate > 0 && html.indexOf(bayes.replace("%s", "100.00")) > 0)
      checkbox.checked = state;
    else if(all == 2 && sstate > 0 && respam.exec(html))
      checkbox.checked = state;
    else if(no == 2 && sstate < 0 && reham.exec(html))
      checkbox.checked = state;
    else if(no && sstate < 0 && html.indexOf(bayes.replace("%s", "0.00")) > 0)
      checkbox.checked = state;
  }
}

function ToggleSelectSpam(mode)
{
  var box = document.getElementById(mode ? "selhambutton" : "selspambutton");
  var state = box.checked;
  var table = document.getElementById("spamtable");
  var lines = table.getElementsByTagName('tr');
  for(var i = 0; i < lines.length; i += 2)
  {
    var checkbox = lines[i].getElementsByTagName('input')[0];
    var sstate = lines[i].className.indexOf("rejected");
    if(mode ? sstate < 0 : sstate >= 0)
      checkbox.checked = state;
  }
}

function setbuttons()
{
  document.getElementById("selallfield").innerHTML =
  "<input type=\"checkbox\" id=\"selallbutton\" onclick=\"ToggleSelect()\"/>";

  document.getElementById("boxes").innerHTML += "<table><tr>"
  +"<td valign=\"center\"><input class=\"spambox\" type=\"checkbox\" id=\"sel100button\""
  + "onclick=\"ToggleSelectPerfect(1,0,'sel100button')\"/><\/td>"
  + "<td class=\"spambox\" valign=\"center\">"+sel100text+"<\/td>"
  +"<td valign=\"center\"><input class=\"spambox\" type=\"checkbox\" id=\"sel90button\""
  + "onclick=\"ToggleSelectPerfect(2,0,'sel90button')\"/><\/td>"
  + "<td class=\"spambox\" valign=\"center\">"+sel90text+"<\/td>"
  +"<td valign=\"center\"><input class=\"hambox\" type=\"checkbox\" id=\"sel10button\""
  + "onclick=\"ToggleSelectPerfect(0,2,'sel10button')\"/><\/td>"
  + "<td class=\"hambox\" valign=\"center\">"+sel10text+"<\/td>"
  + "<td valign=\"center\"><input class=\"hambox\" type=\"checkbox\" id=\"sel0button\""
  + "onclick=\"ToggleSelectPerfect(0,1,'sel0button')\"/><\/td>"
  + "<td class=\"hambox\" valign=\"center\">"+sel0text+"<\/td>"
  + "<\/tr><tr>"
  + "<td valign=\"center\"><input class=\"spambox\" type=\"checkbox\" id=\"selspambutton\""
  + "onclick=\"ToggleSelectSpam(0)\"/><\/td>"
  + "<td colspan=3 class=\"spambox\" valign=\"center\">"+selspamtext+"<\/td>"
  + "<td valign=\"center\"><input class=\"hambox\" type=\"checkbox\" id=\"selhambutton\""
  + "onclick=\"ToggleSelectSpam(1)\"/><\/td>"
  + "<td colspan=3 class=\"hambox\" valign=\"center\">"+selhamtext+"<\/td>"
  + "<\/tr><\/table>";
}

$(document).ready(function() {
  if(document.forms["spammonitorform"].elements["sel"])
  {
    setbuttons();
  }
});
