$(function(){
    $("#reportspam").click(function(){
      var comment = prompt(spamreport_comment,"");
      if(comment == null) { this.href = document.URL; }
      else { this.href += "&comment=" + comment; }
    });
});
