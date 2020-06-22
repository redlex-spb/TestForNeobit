function app() {

	/** Init varible **/

	let cookieID = document.cookie.id,
	    frontendFingerprint = {},
		 pingAttempts = 4,
		 pingMinimal = 0,
	    progressBarInterval,
		 completeData = {},
		 blocksLength = 80,
		 propertyLength = 35;


	/** Loading animation **/
	progressBarInterval = animationProgressBar();


	/** Build fingerprint **/

	if (window.requestIdleCallback) {
		requestIdleCallback(function () {
			Fingerprint2.get(components => sendResult(components));
		})
	} else {
		setTimeout(function () {
			Fingerprint2.get(components => sendResult(components));
		}, 500)
	}


	/** Data consolidation **/

	promiseRequest();
	testPing();
	getWebRTC();



	/*** Basical functions ***/

	/**
	 * Request
	 * @param type string
	 * @param url string
	 * @param async boolean
	 * @param data any
	 * @param contentType string
	 * @param responseType string
	 * @param callback void
	 * @returns any
	 */

	function makeRequest(type, url, async, data, contentType, responseType, callback) {

		let xhr = new XMLHttpRequest();

		xhr.open(type, url, async);

		switch (contentType) {
			case "json":
				xhr.setRequestHeader('Content-Type', 'application/json');
				break;
		}

		if ( responseType ) xhr.responseType = responseType;

		xhr.send(data);
		if (async && url == "/get_nmap") xhr.timeout = 40000;
		else if (async) xhr.timeout = 2000;

		xhr.onload = function() {
			if ( url == "/" ) {
				let headers = xhr.getAllResponseHeaders().split("\n");
				for ( line in headers ) {
					if ( headers[line].indexOf("id: ") > -1 ) {
						if ( saveLocalstorage(headers[line].replace("id: ","")) ) {
							frontendFingerprint.cookie_id = window.localStorage.getItem("cookieID");
						}
					}
				}
			}

			if (callback) return callback(xhr.status,xhr.response);
			else return {status: xhr.status, response: xhr.response};
		};

	}

	async function wait(ms) {
		return new Promise(resolve => {
			setTimeout(resolve, ms);
		});
	}

	function getCookie(name) {
		let matches = document.cookie.match(new RegExp(
			"(?:^|; )" + name.replace(/([\.$?*|{}\(\)\[\]\\\/\+^])/g, '\\$1') + "=([^;]*)"
		));
		return matches ? decodeURIComponent(matches[1]) : undefined;
	}


	/*** Client inspection ***/

	/**
	 * Send fingerprint to server
	 * @param res json
	 */

	function sendResult(res) {

		console.log("frontend Fingerprint",res);

		completeData.Fingerprint2 = res;

		res.forEach(function(element,index){
			frontendFingerprint[element.key] = element.value;
		});

		let values = res.map(function (res) { return res.value });
		let murmur = Fingerprint2.x64hash128(values.join(''), 31);



		makeRequest(
			"POST",
			"/",
			true,
			JSON.stringify(
				{
					hash: murmur,
					res: frontendFingerprint
				}
			),
			"json"
		);
	}

	/**
	 * Check localstorage and save data
	 * @param cookieID string
	 * @returns {boolean}
	 */

	function saveLocalstorage(cookieID) {
		if ( cookieID ) cookieID.toString();
		try {
			if ( !window.localStorage.getItem("cookieID") ) {
				window.localStorage.setItem("cookieID", cookieID);
			}
			if ( !window.sessionStorage.getItem("cookieID") ) {
				window.sessionStorage.setItem("cookieID", cookieID);
			}
			return true;
		} catch (exception) {
			return false;
		}
	}


	/**
	 * Check Proxy
	 */


	function promiseRequest() {
		let index = ["get_nmap", "get_hostname", "get_whois", "get_mac_id", "get_mtu_size", "check_is_tor"],
			url   = "/",
			proms = index.map(d => fetch(url+d));
		Promise.all(proms)
			.then(ps => Promise.all(ps.map(p => p.json())))
			.then(js => js.forEach((j,i) => {
				if ( i == index.length-1 ) {
					onComplete();
				}
			})).catch(rejected => {
				//console.log(rejected);
				onComplete();
		});
	}

	function testPing() {
		let start = Date.now(),
			diff;

		makeRequest("GET","/test_ping",true,false,false,"json",function (status,response) {
			if (status >= 200 && status < 400) {
				diff = response.time - start;
				//console.log("diff",diff);
				if (diff > 0 && (diff < pingMinimal || pingMinimal == 0)) {
					pingMinimal = diff;
				}
				pingAttempts--;
				if(pingAttempts > 0) {
					testPing();
				}
				else {



				}
			}
		});
	}

	async function getWebRTC() {
		let RTCPeerConnection = window.RTCPeerConnection
			|| window.mozRTCPeerConnection
			|| window.webkitRTCPeerConnection
			|| window.msRTCPeerConnection,
			mediaConstraints = {
				optional: [{RtpDataChannels: true}]
			},
			servers = {
				iceServers: [{urls: "stun:stun.l.google.com:19302?transport=udp"}]
			};

		completeData.webrtc = {};

		try {
			let pc = new RTCPeerConnection(servers, mediaConstraints);

			pc.createDataChannel("bl");

			pc.createOffer(function(result){
				pc.setLocalDescription(result,() => {}, () => {});
			}, () => {});

			await wait(3000);

			for ( let line of pc.localDescription.sdp.split('\n') ) {
				if (
					line.indexOf("a=candidate") > -1
					//|| line.indexOf("c=IN") > -1
				) {
					let ip_regex = /([0-9]{1,3}(\.[0-9]{1,3}){3})/,
						ip_regex_exec = ip_regex.exec(line);
					if ( ip_regex_exec && ip_regex_exec.length > 1 ) {

						for (let el of ip_regex_exec) {
							if (/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(el)){
								completeData.webrtc.ip = el;
								return el;
							}
						}
					}
				}
			}
			return false;

		} catch (e) {
			return false;
		}
	}

	function animationProgressBar() {
		let progressBar = document.createElement("SPAN"),
			lengthProgressBar = 20,
			temp = lengthProgressBar,
			timer;

		document.body.innerHTML = "";

		progressBar.id = "progressBar";
		document.body.append("Loading ", progressBar);

		while ( temp != 0 ) {
			if ( temp == lengthProgressBar ) progressBar.innerText = "[";
			progressBar.innerText += "_";
			if ( temp == 1 ) progressBar.innerText += "]";
			temp--;
		}

		timer = setInterval(function () {
			temp++;
			for ( let i = 0; i <= lengthProgressBar; i++ ) {
				if ( i == 0 ) progressBar.innerText = "[";
				if ( i < temp ) progressBar.innerText += "#";
				else progressBar.innerText += "_";
				if ( i == lengthProgressBar ) progressBar.innerText += "]";
				if ( temp == lengthProgressBar+1 ) temp = 0;
			}
		},50);

		return timer;

	}

	function printData() {
		/**
		 * Print title category
		 * @param rowTitle string
		 * @param node object
		 */
		function pasteTitle(rowTitle,node) {
			let temp,
				rowLength = blocksLength,
				rowContent = "",
				middle;

			rowLength -= rowTitle.length + 2;
			middle = Math.round(rowLength/2);
			temp = rowLength;
			while ( temp != 0 ) {
				if (temp == middle) rowContent += ` ${rowTitle} `;
				rowContent += "*";
				temp--;
			}

			node.innerText = rowContent + "\n";
		}

		/**
		 * Print row in category
		 * @param property string
		 * @param value any
		 * @param level number
		 * @param node object
		 * @param subcategoryTitle boolean
		 */
		function pasteRow(property,value,level=1,node,subcategoryTitle=false) {
			let temp,
				spacesLength,
				rowContent = `|`,
				symbol;

			spacesLength = 2*level;
			while ( spacesLength != 0 ) {
				rowContent += " ";
				spacesLength--;
			}

			property = propertyProcessing(property);

			spacesLength = propertyLength;
			rowContent += `${property}:`;
			spacesLength -= property.length + 2 + 2*level;
			if (spacesLength < 0) spacesLength = 1;
			while ( spacesLength != 0 ) {
				rowContent += " ";
				spacesLength--;
			}

			value = valueProcessing(value,subcategoryTitle);

			if ( subcategoryTitle ) symbol = " ";
			else symbol = "=";

			rowContent += `${symbol} ${value}  `;

			spacesLength = blocksLength - propertyLength - value.length - 5;
			if (spacesLength < 0) spacesLength = 1;
			while ( spacesLength != 0 ) {
				rowContent += " ";
				spacesLength--;
			}
			rowContent += "|\n";

			node.innerText += rowContent;
		}

		function pasteEmptyRow(node) {
			let temp,
				rowLength = blocksLength - 2,
				rowContent = "|";

			while ( rowLength != 0 ) {
				rowContent += " ";
				rowLength--;
			}
			rowContent += "|\n";

			node.innerText += rowContent;
		}

		function recursionFor(category,level,node) {
			for (let subcategory in category) {
				if ( typeof category[subcategory] == "object" ) {
					pasteRow(subcategory,"",level,node,true);
					recursionFor(category[subcategory],2,node);
				} else {
					pasteRow(subcategory,category[subcategory],level,node);
				}
			}
		}

		function valueProcessing(value,subcategoryTitle) {
			let temp,temp_str,offset,rowLength;

			if (subcategoryTitle) return "";
			if (typeof value == "undefined") return "-";

			switch (value) {
				case false:
					value = "✗";
					break;
				case true:
					value = "✓";
					break;
				case "":
					value = "-";
					break;
				default:
					value = value.toString();
					break;
			}

			if ( value.length > blocksLength - propertyLength - 5 ) {
				temp = value.length;
				temp_str = "";
				offset = 0;
				while ( temp > blocksLength - propertyLength - 5 ) {
					if ( offset == 0 ) rowLength = blocksLength - propertyLength - 5;
					else  rowLength = blocksLength - 6;
					temp_str += value.slice(offset, offset+rowLength)+"  |\n|  ";
					temp -= blocksLength;
					offset += rowLength;
				}
				if ( value.slice(offset, offset+rowLength).length < rowLength ) {
					temp_str += value.slice(offset, offset+rowLength) + " ".repeat(rowLength - value.slice(offset, offset+rowLength).length - 1);
				} else {
					temp_str += value.slice(offset, offset+rowLength);
				}
				value = temp_str;
			}

			return value;
		}

		function propertyProcessing(property) {
			return property.toUpperCase().replace(/_+/g,' ');
		}

		document.body.innerHTML = "";
		for (let category in completeData.forPrint) {

			this[category] = document.createElement("PRE");
			document.body.append(this[category]);

			pasteTitle(category.toUpperCase(),this[category]);
			pasteEmptyRow(this[category]);

			if ( category == "whois" ) continue;

			if ( typeof completeData.forPrint[category] == "object" ) {
				recursionFor(completeData.forPrint[category],1,this[category]);
			} else {
				pasteRow(category.toUpperCase(),completeData.forPrint[category],1,this[category]);
			}
		}

		if ( completeData.forPrint.whois ) {
			document.querySelectorAll("pre")[document.querySelectorAll("pre").length-1].innerText += completeData.forPrint.whois;
		}

	}

	function onComplete() {
		fetch(`/get_complete_data?webrtc_ip=${completeData.webrtc.ip}&cookie_id=${localStorage.cookieID}`)
			.then(response=>response.json())
			.then(data=>{
				console.log(data);

				completeData.forPrint = data;
				completeData.forPrint.vulnerabilities.javascript = true;
				completeData.forPrint.proxy.webrtc.ip = completeData.webrtc.ip;

				if ( completeData.webrtc.ip ) {
					completeData.forPrint.vulnerabilities.webrtc = true;
				}

				if ( !completeData.forPrint.detected_anonymizers.tor ) {
					if (
						(!completeData.forPrint.proxy.proxy_headers
							&& !completeData.forPrint.nmap.open_proxy_ports)
						&&	(completeData.forPrint.nmap.open_vpn_ports
							|| (typeof completeData.forPrint.whois != "undefined" && completeData.forPrint.whois.indexOf('mnt-by: OPERA') > -1)
							|| (
									completeData.forPrint.proxy.timezone.backend
									&& completeData.forPrint.proxy.timezone.frontend
									&& completeData.forPrint.proxy.timezone.backend != completeData.forPrint.proxy.timezone.frontend
								)
							|| (
								typeof completeData.forPrint.proxy.webrtc.ip != "undefined"
								&& completeData.forPrint.proxy.webrtc.ip != completeData.forPrint.http.ip
							)
						)
					) { completeData.forPrint.detected_anonymizers.vpn = true; }

					if ( !completeData.forPrint.detected_anonymizers.vpn
						&& (
							completeData.forPrint.proxy.proxy_headers
							|| completeData.forPrint.nmap.open_proxy_ports
							|| (
								completeData.forPrint.proxy.timezone.backend
								&& completeData.forPrint.proxy.timezone.frontend
								&& completeData.forPrint.proxy.timezone.backend != completeData.forPrint.proxy.timezone.frontend
							)
							|| (
								typeof completeData.forPrint.proxy.webrtc.ip != "undefined"
								&& completeData.forPrint.proxy.webrtc.ip != completeData.forPrint.http.ip
							)
						)
					){ completeData.forPrint.detected_anonymizers.proxy = true; }
				}

				completeData.forPrint.visitor_information.data_create = new Date(completeData.forPrint.visitor_information.data_create).toUTCString();
				completeData.forPrint.visitor_information.last_visit = new Date(completeData.forPrint.visitor_information.last_visit).toUTCString();


				//completeData.forPrint.proxy.tor = completeData.tor.is_tor;
				completeData.forPrint.proxy.ping = pingMinimal;


				clearInterval(progressBarInterval);
				printData();
			}).catch(rejected => {
			console.log(rejected);
		});
	}

}


/** Running inspection **/

document.addEventListener("DOMContentLoaded", app);