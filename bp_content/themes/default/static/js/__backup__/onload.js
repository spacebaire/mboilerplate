(function(){
 	//    FONT LOADERS
    WebFont.load({
        google: {
          families: ['Droid Sans', 'Droid Serif']
        },
        custom: {
          families: ['Roboto-Black','Roboto-BlackItalic','Roboto-Bold','Roboto-BoldItalic','Roboto-Italic','Roboto-Light','Roboto-LightItalic','Roboto-Medium','Roboto-MediumItalic','Roboto-Regular','Roboto-Thin','Roboto-ThinItalic','BryantPro-Bold','BryantPro-Light','BryantPro-Medium','BryantPro-Regular']
        }
    });
    
    //    BROWSER GETTER
	var BrowserDetect = {
		init: function() {
			this.browser = this.searchString(this.dataBrowser) || "An unknown browser";
			this.version = this.searchVersion(navigator.userAgent) || this.searchVersion(navigator.appVersion) || "an unknown version";
			this.OS = this.searchString(this.dataOS) || "an unknown OS";
			console.log("browser: " + this.browser + " v." + this.version + " running in " + this.OS);
			if (this.browser != 'Chrome' && this.browser != 'Safari' && this.browser != 'Firefox') {
				alert("Este sistema ha sido diseñado para plataformas diferentes a la tuya, descarga Google Chrome, Mozilla Firefox, o Safari para poder navegar.")
			}
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



// function invictusOnload(hrefLeft, hrefRight){
//     //  $(window).scroll(function() {
//     //     if ($(this).scrollTop() > 1){  
//     //         $('.toolbar').addClass("toolbarScrolled");
//     //         $('.settings').addClass("settingsScrolled");
//     //         $('.middle').addClass("middleScrolled");
//     //         $('.section-name').addClass("section-nameScrolled");
//     //         $('.section-controls').addClass("section-controlsScrolled");
//     //         document.getElementById('logoIcon2').size=40;
//     //         if (screen.width < 480){
//     //             document.getElementById('user').size=24;
//     //             document.getElementById('home').size=24;
//     //             document.getElementById('actions').size=24;
//     //             document.getElementById('community').size=24;
//     //             document.getElementById('box').size=24;
//     //             document.getElementById('ppa').size=24;
//     //             document.getElementById('qubit').size=24;
//     //         } 
//     //       }
//     //       else{
//     //         $('.toolbar').removeClass("toolbarScrolled");
//     //         $('.settings').removeClass("settingsScrolled");
//     //         $('.middle').removeClass("middleScrolled");
//     //         $('.section-name').removeClass("section-nameScrolled");
//     //         $('.section-controls').removeClass("section-controlsScrolled");
//     //         document.getElementById('logoIcon2').size=70;
//     //         if (screen.width < 480){
//     //             document.getElementById('user').size=36;
//     //             document.getElementById('home').size=36;
//     //             document.getElementById('actions').size=36;
//     //             document.getElementById('community').size=36;
//     //             document.getElementById('box').size=36;
//     //             document.getElementById('ppa').size=36;
//     //             document.getElementById('qubit').size=36;
//     //         } 
//     //       }
//     // });
    
// // //    KEYBOARD NAVIGATION   
// //     $( document ).on( "keyup", function(event) {
// //         switch (event.which){
// //             case 37: //Left
// //                         window.open(hrefLeft, "_self")
// //                         break;
// //             case 39: //Right
// //                         window.open(hrefRight, "_self")
// //                         break;
// //             default: break;
        
// //         }
        
// //     });
// }


//  