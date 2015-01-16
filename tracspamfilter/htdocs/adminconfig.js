$(document).ready(function() {
  $("#purge_age").enable($("#logging_enabled").checked());
  $("#spam_monitor_entries").enable($("#logging_enabled").checked());
  $("#logging_enabled").click(function() {
    $("#purge_age").enable(this.checked);
    $("#spam_monitor_entries").enable(this.checked);
  });
  $("#authenticated_karma").enable(!$("#trust_authenticated").checked());
  $("#trust_authenticated").click(function() {
    $("#authenticated_karma").enable(!this.checked);
  });
});
