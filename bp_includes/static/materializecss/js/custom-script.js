/*================================================================================
	Item Name: Materialize - Material Design Admin Template
	Version: 3.1
	Author: GeeksLabs
	Author URL: http://www.themeforest.net/user/geekslabs
================================================================================

NOTE:
------
PLACE HERE YOUR OWN JS CODES AND IF NEEDED.
WE WILL RELEASE FUTURE UPDATES SO IN ORDER TO NOT OVERWRITE YOUR CUSTOM SCRIPT IT'S BETTER LIKE THIS. */


$(document).ready(function() {

	WebFont.load({
		custom: {
			families: ['Roboto-Black','Roboto-BlackItalic','Roboto-Bold','Roboto-BoldItalic','Roboto-Italic','Roboto-Light','Roboto-LightItalic','Roboto-Medium','Roboto-MediumItalic','Roboto-Regular','Roboto-Thin','Roboto-ThinItalic']
		}
	});

	// Pikadate datepicker
	$('.datepicker').pickadate({
		selectMonths: true, // Creates a dropdown to control month
		selectYears: 80, // Creates a dropdown of years to control year
		format: 'yyyy-mm-dd', // Creates adequate html5 default formatting
		formatSubmit: 'yyyy-mm-dd', // Creates adequate html5 default formatting
		// monthsFull: ['Enero', 'Febrero', 'Marzo', 'Abril', 'Mayo', 'Junio', 'Julio', 'Agosto', 'Septiembre', 'Octubre', 'Noviembre', 'Diciembre'],
		// monthsShort: ['Ene', 'Feb', 'Mar', 'Abr', 'May', 'Jun', 'Jul', 'Ago', 'Sep', 'Oct', 'Nov', 'Dic'],
		// weekdaysFull: ['Domingo', 'Lunes', 'Martes', 'Miércoles', 'Jueves', 'Viernes', 'Sábado'],
		// weekdaysShort: ['Dom', 'Lun', 'Mar', 'Mie', 'Jue', 'Vie', 'Sab'],
		// today: 'Hoy',
		// clear: '',
		// close: 'Cerrar',
		dateMin: false,
		dateMax: true,
		max: new Date()
		// // Strings and translations
		// monthsFull: [ 'January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December' ],
		// monthsShort: [ 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec' ],
		// weekdaysFull: [ 'Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday' ],
		// weekdaysShort: [ 'Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat' ],
		// // Display strings
		// monthPrev: '&#9664;',
		// monthNext: '&#9654;',
		// showMonthsFull: true,
		// showWeekdaysShort: true,
		// // Today and clear
		// today: 'Today',
		// clear: 'Clear',
		// // Date formats
		// format: 'd mmmm, yyyy',
		// formatSubmit: false,
		// hiddenSuffix: '_submit',
		// // First day of week
		// firstDay: 0,
		// // Month & year dropdown selectors
		// monthSelector: false,
		// yearSelector: false,
		// // Date ranges
		// dateMin: false,
		// dateMax: false,
		// // Dates disabled
		// datesDisabled: false,
		// // Disable picker
		// disablePicker: false,
		// // Calendar events
		// onStart: null,
		// onOpen: null,
		// onClose: null,
		// onSelect: null,
		// // Themes
		// klass: {
		//     active: 'pickadate__active',
		//     input: 'pickadate__input',
		//     // Picker holder states
		//     holder: 'pickadate__holder',
		//     opened: 'pickadate__holder--opened',
		//     focused: 'pickadate__holder--focused',
		//     // Picker frame and wrapper
		//     frame: 'pickadate__frame',
		//     wrap: 'pickadate__wrap',
		//     // Picker calendar
		//     calendar: 'pickadate__calendar',
		//     // Picker header
		//     header: 'pickadate__header',
		//     // Month navigation
		//     monthPrev: 'pickadate__nav--prev',
		//     monthNext: 'pickadate__nav--next',
		//     // Month & year labels
		//     month: 'pickadate__month',
		//     year: 'pickadate__year',
		//     // Select menus
		//     selectMonth: 'pickadate__select--month',
		//     selectYear: 'pickadate__select--year',
		//     // Picker table
		//     table: 'pickadate__table',
		//     // Weekday labels
		//     weekdays: 'pickadate__weekday',
		//     // Calendar body
		//     body: 'pickadate__body',
		//     // Day states
		//     day: 'pickadate__day',
		//     dayDisabled: 'pickadate__day--disabled',
		//     daySelected: 'pickadate__day--selected',
		//     dayHighlighted: 'pickadate__day--highlighted',
		//     dayToday: 'pickadate__day--today',
		//     dayInfocus: 'pickadate__day--infocus',
		//     dayOutfocus: 'pickadate__day--outfocus',
		//     // Footer
		//     footer: 'pickadate__footer',
		//     // Today and clear buttons
		//     buttonClear: 'pickadate__button--clear',
		//     buttonToday: 'pickadate__button--today'
		// }
	});

	// Modal triggers on close, hide any overlay leftover
	$('.modal-trigger').leanModal({
		complete: function() { 
		$('.lean-overlay').hide();
		} // Callback for Modal close
	});

});

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

function cleanUpMailSpecialChars(str){
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
	return str;
}

function addCommas(val) {
  while (/(\d+)(\d{3})/.test(val.toString())) {
    var val = val.toString().replace(/(\d+)(\d{3})/, '$1' + ',' + '$2');
  }
  return val;
}

function toggleVis(id){
	if (document.getElementById(id).style.display == 'none'){
	    document.getElementById(id).style.display = 'block';
		document.getElementById(id).style.opacity = 1;
	}else{
	    document.getElementById(id).style.display = 'none';
		document.getElementById(id).style.opacity = 0;
	}
}

function getUrlVars(){
    var vars = [], hash;
    var hashes = window.location.href.slice(window.location.href.indexOf('?') + 1).split('&');
    for(var i = 0; i < hashes.length; i++)
    {
        hash = hashes[i].split('=');
        vars.push(hash[0]);
        vars[hash[0]] = hash[1];
        if (vars[hash[0]]) if (vars[hash[0]].search(/#/) != -1) vars[hash[0]]=vars[hash[0]].substr(0,vars[hash[0]].search(/#/));
    }
    return vars;
}