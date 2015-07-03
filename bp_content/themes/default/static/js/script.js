/** MAIN **/
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

function cleanUpNumbers(str){
	return str.replace(/\d+/g, '');
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


function toggleVis(id){
	if (document.getElementById(id).style.display == 'none')
	    document.getElementById(id).style.display = 'block';
	else
	    document.getElementById(id).style.display = 'none';
}

// ONLOAD METHODS

(function(){
 	//    FONT LOADERS
    WebFont.load({
        google: {
          families: ['Droid Sans', 'Droid Serif']
        },
        custom: {
          families: ['Lato','Roboto-Black','Roboto-BlackItalic','Roboto-Bold','Roboto-BoldItalic','Roboto-Italic','Roboto-Light','Roboto-LightItalic','Roboto-Medium','Roboto-MediumItalic','Roboto-Regular','Roboto-Thin','Roboto-ThinItalic','BryantPro-Bold','BryantPro-Light','BryantPro-Medium','BryantPro-Regular']
        }
    });
    
    //    BROWSER GETTER
	var BrowserDetect = {
		init: function() {
			this.browser = this.searchString(this.dataBrowser) || "An unknown browser";
			this.version = this.searchVersion(navigator.userAgent) || this.searchVersion(navigator.appVersion) || "an unknown version";
			this.OS = this.searchString(this.dataOS) || "an unknown OS";
			console.log("browser: " + this.browser + " v." + this.version + " running in " + this.OS);
			if (this.browser != 'Chrome' && this.browser.indexOf('Safari') == -1 && this.browser.indexOf('iPhone') == -1 && this.browser != 'Firefox') {
				alert("Lo sentimos, pero el sistema no ha sido diseñado para tu plataforma, descarga Google Chrome para poder navegar en Invictus.");
			}
			else if (this.browser.indexOf("Safari") != -1)
				is_Safari = true;
			else if (this.browser.indexOf("Chrome") == -1)
				not_Chrome = true;
		},
		searchString: function(data) {
			for (var i = 0; i < data.length; i++) {
				var dataString = data[i].string;
				var dataProp = data[i].prop;
				this.versionSearchString = data[i].versionSearch || data[i].identity;
				if (dataString) {
					if (dataString.indexOf(data[i].subString) != -1) return data[i].identity;
				} else if (dataProp) return data[i].identity;
			}
		},
		searchVersion: function(dataString) {
			var index = dataString.indexOf(this.versionSearchString);
			if (index == -1) return;
			return parseFloat(dataString.substring(index + this.versionSearchString.length + 1));
		},
		dataBrowser: [{
			string: navigator.userAgent,
			subString: "Chrome",
			identity: "Chrome"
		}, {
			string: navigator.userAgent,
			subString: "OmniWeb",
			versionSearch: "OmniWeb/",
			identity: "OmniWeb"
		}, {
			string: navigator.vendor,
			subString: "Apple",
			identity: "Safari",
			versionSearch: "Version"
		}, {
			prop: window.opera,
			identity: "Opera",
			versionSearch: "Version"
		}, {
			string: navigator.vendor,
			subString: "iCab",
			identity: "iCab"
		}, {
			string: navigator.vendor,
			subString: "KDE",
			identity: "Konqueror"
		}, {
			string: navigator.userAgent,
			subString: "Firefox",
			identity: "Firefox"
		}, {
			string: navigator.vendor,
			subString: "Camino",
			identity: "Camino"
		}, { // for newer Netscapes (6+)
			string: navigator.userAgent,
			subString: "Netscape",
			identity: "Netscape"
		}, {
			string: navigator.userAgent,
			subString: "MSIE",
			identity: "Explorer",
			versionSearch: "MSIE"
		}, {
			string: navigator.userAgent,
			subString: "Gecko",
			identity: "Mozilla",
			versionSearch: "rv"
		}, { // for older Netscapes (4-)
			string: navigator.userAgent,
			subString: "Mozilla",
			identity: "Netscape",
			versionSearch: "Mozilla"
		}],
		dataOS: [{
			string: navigator.platform,
			subString: "Win",
			identity: "Windows"
		}, {
			string: navigator.platform,
			subString: "Mac",
			identity: "Mac"
		}, {
			string: navigator.userAgent,
			subString: "iPhone",
			identity: "iPhone/iPod"
		}, {
			string: navigator.platform,
			subString: "Linux",
			identity: "Linux"
		}]
	};
	BrowserDetect.init();	
	   
 })();

