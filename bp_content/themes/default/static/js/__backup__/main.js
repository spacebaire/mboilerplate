function passValue(_elem){
  if (_elem.tagName.indexOf('CHECKBOX') != -1)
    document.getElementById(_elem.id.substr(1)).checked = _elem.checked;
  else if  (_elem.tagName.indexOf('RADIO') != -1)
    document.getElementById(_elem.id.substr(1)).value = _elem.selected;
  else if(_elem.value)
  		document.getElementById(_elem.id.substr(1)).value = _elem.value;			
}

function cleanUpSpecialChars(str){
	str = str.replace(/[ÀÁÂÃÄÅ]/g,"A");
	str = str.replace(/[àáâãäå]/g,"a");
	str = str.replace(/[ÈÉÊË]/g,"E");
	str = str.replace(/[éèëê]/g,"e");
	str = str.replace(/[ÍÌÎÏ]/g,"I");
	str = str.replace(/[íîïì]/g,"i");
	str = str.replace(/[ÓÖÒÔ]/g,"O");
	str = str.replace(/[óòôö]/g,"o");
	str = str.replace(/[ÚÜÛÙ]/g,"U");
	str = str.replace(/[úùûü]/g,"u");
	str = str.replace(/[Ñ]/g,"N");
	str = str.replace(/[ñ]/g,"n");
	str = str.replace(/[Ç]/g,"C");
	str = str.replace(/[ç]/g,"c");
	return str.replace(/[^a-zA-Z0-9 ]/g, "");
}

function addCommas(val) {
  while (/(\d+)(\d{3})/.test(val.toString())) {
    var val = val.toString().replace(/(\d+)(\d{3})/, '$1' + ',' + '$2');
  }
  return val;
}

function removeHC(element_id){
  var tags = document.getElementById(element_id).getElementsByTagName("text");
  for (var i = 0; i < tags.length; i++) {
    var index = tags[i].innerHTML.indexOf("Highcharts.com");
    if (index != -1) {
       tags[i].innerHTML = "";
       break;
    }
  } 
}
//HELPERS
Date.daysBetween = function( date1, date2 ) {
      //Get 1 day in milliseconds
      var one_day=1000*60*60*24;

      // Convert both dates to milliseconds
      var date1_ms = date1.getTime();
      var date2_ms = date2.getTime();

      // Calculate the difference in milliseconds
      var difference_ms = date2_ms - date1_ms;

      // Convert back to days and return
      return Math.round(difference_ms/one_day); 
}
function enterpressEvent(e, form){
  var code = (e.keyCode ? e.keyCode : e.which);
  if(code == 13) { //Enter keycode
    sendForm(form);
  }
}