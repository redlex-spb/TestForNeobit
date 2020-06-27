function app() {

	/** Init varible **/

	const blocksLength = config.blocksLength,
			propertyLength = config.propertyLength,
			checkUrls = config.checkUrls,
			lengthProgressBar = config.lengthProgressBar;

	let pingAttempts = config.pingAttempts,
		 pingMinimal = 0,
	    progressBarInterval,
		 completeData = {},
		 progressBarPercent;


	/** Loading animation **/
	progressBarInterval = animationProgressBar();


	/** Build fingerprint **/

	if (window.requestIdleCallback) {
		requestIdleCallback(function () {
			try {
				Fingerprint2.get(components => sendResult(components));
			} catch (e) {
				let navigatorArray = [];
				for ( let prop in navigator ) {
					navigatorArray.push({key: prop, value: navigator[prop]});
				}
				sendResult(navigatorArray);
			}
		})
	} else {
		setTimeout(function () {
			try {
				Fingerprint2.get(components => sendResult(components));
			} catch (e) {
				let navigatorArray = [];
				for ( let prop in navigator ) {
					navigatorArray.push({key: prop, value: navigator[prop]});
				}
				navigatorArray.push({key: "timezone", value: Intl.DateTimeFormat().resolvedOptions().timeZone});
				sendResult(navigatorArray);
			}
		}, 500)
	}


	/** Data consolidation **/

	getWebRTC();


	/*** Basical functions ***/

	/**
	 * Request
	 * @param type {string}
	 * @param url {string}
	 * @param async {boolean}
	 * @param data {any}
	 * @param contentType {string}
	 * @param responseType {string}
	 * @param callback {void}
	 * @returns {any}
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
			if (callback) return callback(xhr.status,xhr.response);
			else return {status: xhr.status, response: xhr.response};
		};

	}

	/**
	 * Sleep
	 * @param ms {number}
	 * @returns {Promise}
	 */
	async function wait(ms) {
		return new Promise(resolve => {
			setTimeout(resolve, ms);
		});
	}

	/**
	 * Save data in localstorage
	 * @param key {string}
	 * @param data {string}
	 * @returns {boolean}
	 */
	function setInLocalStorage(key,data) {
		if ( !data || !key ) return false;
		data = data.toString();
		key = key.toString();
		try {
			if ( !localStorage.getItem(key) ) {
				localStorage.setItem(key, data);
			}
			if ( !sessionStorage.getItem(key) ) {
				sessionStorage.setItem(key, data);
			}
			return true;
		} catch (exception) {
			console.log("setInLocalStorage exception:",exception);
			return false;
		}
	}

	/**
	 * Get data in localstorage
	 * @param key {string}
	 * @returns {string|boolean}
	 */
	function getInLocalStorage(key) {
		if ( !key ) return false;
		key.toString();
		try {
			if ( localStorage.getItem(key) ) {
				return localStorage.getItem(key);
			}
			if ( sessionStorage.getItem(key) ) {
				return sessionStorage.getItem(key);
			}
		} catch (exception) {
			console.log("getInLocalStorage exception:",exception);
			return false;
		}
	}

	/*** Client inspection ***/

	/**
	 * Send fingerprint to server
	 * @param res {object}
	 */

	function sendResult(res) {

		console.log("frontend Fingerprint",res);

		let frontendFingerprint = {},
			 values = res.map(res => { return res.value }),
			 murmur;

		completeData.Fingerprint2 = res;

		for ( let i in res ) {
			frontendFingerprint[res[i].key] = res[i].value;
		}

		if ( window.navigator.doNotTrack == "1" ) frontendFingerprint.doNotTrack = true;
		else frontendFingerprint.doNotTrack = false;

		if ( navigator.languages ) frontendFingerprint.languages = navigator.languages.slice().sort().join();
		if ( navigator.cookieEnabled ) frontendFingerprint.cookieEnabled = navigator.cookieEnabled;

		if
		(
			location.hostname != config.host_url.replace(/(http|https)(:\/\/)([\d\.]+|([\w+\.\w+]+))(\/)?/,"$3")
		)
		{
			frontendFingerprint.webproxy = true;
		}


		try {
			murmur = Fingerprint2.x64hash128(values.join(''), 31);
		} catch (e) {
			murmur = btoa(values.join('')).slice(0,30);
		}

		makeRequest(
			"POST",
			config.host_url,
			true,
			JSON.stringify(
				{
					hash: murmur,
					res: frontendFingerprint
				}
			),
			"json",
			false,
			() => {promiseRequest();testPing();}
		);
	}

	/**
	 * Make async request
	 */
	function promiseRequest() {

		let complete = 0;

		for ( let i in checkUrls ) {

			fetch(config.host_url + checkUrls[i])
				.then(response=>response.json())
				.then(data=> {
					progressBarPercent.innerText = checkUrls[i] != "get_nmap"
						? parseInt(progressBarPercent.innerText) + 10
						: parseInt(progressBarPercent.innerText) + (10-(checkUrls.length-1))*10;

					complete++;

					if ( complete == checkUrls.length ) {
						onComplete();
					}
				})
				.catch(rejected=>{
					console.log("rejected",rejected,checkUrls[i]);

					progressBarPercent.innerText = checkUrls[i] != "get_nmap"
						? parseInt(progressBarPercent.innerText) + 10
						: parseInt(progressBarPercent.innerText) + (10-(checkUrls.length-1))*10;

					complete++;

					if ( complete == checkUrls.length ) {
						onComplete();
					}
				})
		}
	}

	/**
	 * Time difference when sending and receiving
	 */
	function testPing() {
		let start = Date.now(),
			diff;

		makeRequest("GET",`${config.host_url}test_ping`,true,false,false,"json",function (status,response) {
			if (status >= 200 && status < 400) {
				diff = response.time - start;
				if (diff > 0 && (diff < pingMinimal || pingMinimal == 0)) {
					pingMinimal = diff;
				}
				pingAttempts--;
				if(pingAttempts > 0) {
					testPing();
				}
			}
		});
	}

	/**
	 * Get local and public IP client
	 * @returns {Promise<boolean>}
	 */
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

		completeData.webrtc = {ip: []};
		//completeData.webrtc.ip = [];

		try {
			let pc = new RTCPeerConnection(servers, mediaConstraints);

			pc.createDataChannel("bl");

			pc.createOffer(function(result){
				pc.setLocalDescription(result,() => {}, () => {});
			}, () => {});

			await wait(1000);

			for ( let line of pc.localDescription.sdp.split('\n') ) {
				if (
					line.indexOf("a=candidate") > -1
					//|| line.indexOf("c=IN") > -1
				) {
					let ip_regex = /([0-9]{1,3}(\.[0-9]{1,3}){3})/,
						ip_regex_exec = ip_regex.exec(line);
					if ( ip_regex_exec && ip_regex_exec.length > 1 ) {

						for (let el of ip_regex_exec) {
							if (
								/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(el)
								&& completeData.webrtc.ip.indexOf(el) == -1
							)
							{
								completeData.webrtc.ip.push(el);
							}
						}
					}
				}
			}
			return true;

		} catch (e) {
			return false;
		}
	}

	/*** Visualization ***/

	/**
	 * Print progress bar
	 * @returns {number}
	 */
	function animationProgressBar() {
		let progressBar = document.createElement("SPAN"),
			temp = lengthProgressBar-3,
			timer,
			progressBarWrapper = document.createElement("DIV");

		document.getElementById("backend").style.display = "none";

		progressBarWrapper.id = "loading";

		progressBarPercent = document.createElement("SPAN");
		progressBarPercent.id = "loading_percent";
		progressBarPercent.innerText = 0;

		progressBarWrapper.append("Loading ", progressBar, " ", progressBarPercent, "%");
		document.body.append(progressBarWrapper);

		progressBar.innerText = "["+"_".repeat(lengthProgressBar-2)+"]";

		timer = setInterval(function () {
			temp++;

			progressBar.innerText = "["+"#".repeat(temp)+"_".repeat(lengthProgressBar-temp-2)+"]";
			if ( temp == lengthProgressBar-2 ) temp = 0;

		},50);

		return timer;

	}

	/**
	 * Print full data
	 */
	function printData() {
		/**
		 * Print title category
		 * @param rowTitle {string}
		 * @param node {object}
		 */
		function pasteTitle(rowTitle,node) {
			let temp,
				rowLength = blocksLength,
				rowContent = "",
				middle;

			rowLength -= rowTitle.length + 2;
			rowContent = `${"*".repeat(Math.round(rowLength/2))} ${rowTitle} ${"*".repeat(rowLength/2)}`;

			node.innerText = rowContent + "\n";
		}

		/**
		 * Print row in category
		 * @param property {string}
		 * @param value {any}
		 * @param level {number}
		 * @param node {object}
		 * @param subcategoryTitle {boolean}
		 */
		function pasteRow(property,value,level=1,node,subcategoryTitle=false) {
			let temp,
				spacesLength,
				rowContent = `|`,
				symbol;

			rowContent += " ".repeat(2*level);

			property = propertyProcessing(property);
			rowContent += `${property}:`;

			if ( (propertyLength - (property.length + 2 + 2*level)) > 0 ) {
				rowContent += " ".repeat(propertyLength - (property.length + 2 + 2*level));
			}

			value = valueProcessing(value,subcategoryTitle);

			if ( subcategoryTitle ) symbol = " ";
			else symbol = "=";

			rowContent += `${symbol} ${value}  `;

			if ( (blocksLength - propertyLength - value.length - 5) > 0 ) {
				rowContent += " ".repeat(blocksLength - propertyLength - value.length - 5);
			}

			rowContent += "|\n";

			node.innerText += rowContent;
		}

		/**
		 * Print empty row
		 * @param node {object}
		 */
		function pasteEmptyRow(node) {
			node.innerText += `|${" ".repeat(blocksLength - 2)}|\n`;
		}

		/**
		 * Recursion print category
		 * @param category {any}
		 * @param level {number}
		 * @param node {object}
		 */
		function recursionFor(category,level,node) {
			for (let subcategory in category) {
				if ( typeof category[subcategory] == "object" ) {
					pasteRow(subcategory,"",level,node,true);
					recursionFor(category[subcategory],level+1,node);
				} else {
					pasteRow(subcategory,category[subcategory],level,node);
				}
			}
		}

		/**
		 * Processing value
		 * @param value {string}
		 * @param subcategoryTitle {boolean}
		 * @returns {string}
		 */
		function valueProcessing(value,subcategoryTitle) {
			let temp,temp_str,offset,rowLength;

			if (subcategoryTitle) return "";
			if (value == undefined) return "-";

			switch (value) {
				case false:
					value = "✗";
					break;
				case true:
					value = "✓";
					break;
				case "undefined":
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
					rowLength = blocksLength - propertyLength - 5;
					temp_str += `${value.slice(offset, offset+rowLength)}  |\n|  ${" ".repeat(propertyLength-1)}`;
					temp -= value.slice(offset, offset+rowLength).length;
					offset += rowLength;
				}
				if ( value.slice(offset, offset+rowLength).length < rowLength ) {
					temp_str += value.slice(offset, offset+rowLength) + " ".repeat(rowLength - value.slice(offset, offset+rowLength).length);
				} else {
					temp_str += value.slice(offset, offset+rowLength);
				}
				value = temp_str;
			}

			return value;
		}

		/**
		 * Processing property
		 * @param property {string}
		 * @returns {string}
		 */
		function propertyProcessing(property) {
			return property.toUpperCase().replace(/_+/g,' ');
		}


		document.getElementById("loading").style.display = "none";
		let frontend = document.createElement("DIV");
		frontend.id = "frontend";
		document.body.append(frontend);

		for (let category in completeData.forPrint) {

			this[category] = document.createElement("PRE");
			frontend.append(this[category]);

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
			document.querySelectorAll("#frontend pre")[document.querySelectorAll("#frontend pre").length-1].innerText += completeData.forPrint.whois;
		}

	}


	/*** Finish processing ***/

	/**
	 * Complete processing
	 */
	function onComplete() {
		if ( completeData.webrtc.ip.length > 0 ) {
			if ( completeData.webrtc.ip.length > 1 ) {
				completeData.webrtc.ip = {
					local: completeData.webrtc.ip[0],
					public: completeData.webrtc.ip[1]
				};
			} else {
				completeData.webrtc.ip = {public: completeData.webrtc.ip[0]};
			}
		}

		completeData.real_ip = getInLocalStorage("real_ip");

		fetch(
			`${config.host_url}get_complete_data`+
			`?webrtc_ip=${completeData.webrtc.ip.public}`+
			`&cookie_id=${localStorage.cookieID}`+
			`&real_ip=${completeData.real_ip}`
		)
			.then(response=>response.json())
			.then(data=>{
				console.log("complete data from server",data);

				completeData.forPrint = data;

				if
				(
					completeData.forPrint.visitor_information.cookie_id
					&& !localStorage.cookieID
				)
				{
					setInLocalStorage("cookieID",completeData.forPrint.visitor_information.cookie_id)
				}

				if
				(
					completeData.forPrint.visitor_information.real_ip
				)
				{
					setInLocalStorage("real_ip",completeData.forPrint.visitor_information.real_ip);
				}

				if ( completeData.webrtc != undefined ) {
					completeData.forPrint.vulnerabilities.webrtc = true;
				}

				completeData.platform = {
					useragent_backend: setPlatform(completeData.forPrint.device_info.useragent.backend.os),
					useragent_frontend: setPlatform(completeData.forPrint.device_info.useragent.frontend.os),
					js: setPlatform(completeData.forPrint.device_info.js.platform),
					nmap: setPlatform(completeData.forPrint.nmap.data.osNmap)
				};

				completeData.forPrint.proxy.lied_platform = detectLiedPlatform(completeData.platform);

				revealVPN();
				revealProxy();

				completeData.forPrint.visitor_information.date_create = new Date(completeData.forPrint.visitor_information.date_create).toUTCString();
				completeData.forPrint.visitor_information.last_visit = new Date(completeData.forPrint.visitor_information.last_visit).toUTCString();

				completeData.forPrint.proxy.ping = pingMinimal;

				clearInterval(progressBarInterval);
				printData();

			})
			.catch(async rejected => {

				await wait(1000);

				console.log("fetch complete_data rejected:",rejected);

			   clearInterval(progressBarInterval);
			   completeData.forPrint = data;

			   console.log("data backend",data);

			   alternativeFingerprint();
			   revealVPN();
			   revealProxy();

			   printData();

			});
	}

	/**
	 * Compare data for detect proxy
	 */
	function revealProxy() {
		if (
				!completeData.forPrint.detected_anonymizers.tor
				&& !completeData.forPrint.detected_anonymizers.vpn
				&&
				(
					completeData.forPrint.proxy.hostname.dns != undefined
						? completeData.forPrint.proxy.hostname.dns.indexOf("vpn") == -1
						: true
				)
				&&
				(
					completeData.forPrint.nmap.data.hostname != undefined
						? completeData.forPrint.nmap.data.hostname.indexOf("vpn") == -1
						: true
				)
				&&
				(
					completeData.forPrint.proxy.webproxy
					|| completeData.forPrint.proxy.proxy_headers
					|| completeData.forPrint.nmap.open_proxy_ports
					||
					(
						completeData.forPrint.proxy.hostname.dns
						&& completeData.forPrint.proxy.hostname.dns.indexOf("proxy") > -1
					)
					||
					(
						completeData.forPrint.nmap.data.hostname
						&& completeData.forPrint.nmap.data.hostname.indexOf("proxy") > -1
					)
					||
					(
						completeData.forPrint.proxy.useragent.backend
						&& completeData.forPrint.proxy.useragent.frontend
						&& completeData.forPrint.proxy.useragent.backend != completeData.forPrint.proxy.useragent.frontend
					)
					||
					(
						completeData.forPrint.proxy.timezone.backend
						&& completeData.forPrint.proxy.timezone.frontend
						&& completeData.forPrint.proxy.timezone.backend != completeData.forPrint.proxy.timezone.frontend
					)
					||
					(
						completeData.forPrint.proxy.language.backend
						&& completeData.forPrint.proxy.language.frontend
						&& completeData.forPrint.proxy.language.backend != completeData.forPrint.proxy.language.frontend
					)
					||
					(
						completeData.forPrint.proxy.webrtc.ip.length > 0
						&& completeData.forPrint.proxy.webrtc.ip.public != completeData.forPrint.http.ip
					)
					||
					(
						completeData.forPrint.visitor_information.real_ip
						&& completeData.forPrint.visitor_information.real_ip != completeData.forPrint.http.ip
					)
				)
		)
		{
			completeData.forPrint.detected_anonymizers.proxy = true;
		}
	}

	/**
	 * Compare data for detect VPN
	 */
	function revealVPN() {
		if (!completeData.forPrint.detected_anonymizers.tor) {
			if (
					(
						!completeData.forPrint.proxy.proxy_headers
						&& !completeData.forPrint.nmap.open_proxy_ports
						&& !completeData.forPrint.proxy.webproxy
						&&
						(
							completeData.forPrint.proxy.hostname.dns != undefined
								? completeData.forPrint.proxy.hostname.dns.indexOf("proxy") == -1
								: true
						)
						&&
						(
							completeData.forPrint.nmap.data.hostname != undefined
								? completeData.forPrint.nmap.data.hostname.indexOf("proxy") == -1
								: true
						)
					)
					&&
					(
						completeData.forPrint.nmap.open_vpn_ports
						||
						(
							typeof completeData.forPrint.whois != "undefined"
							&& completeData.forPrint.whois.indexOf('mnt-by: OPERA') > -1
						)
						||
						(
							completeData.forPrint.proxy.hostname.dns
							&& completeData.forPrint.proxy.hostname.dns.indexOf("vpn") > -1
						)
						||
						(
							completeData.forPrint.nmap.data.hostname
							&& completeData.forPrint.nmap.data.hostname.indexOf("vpn") > -1
						)
						||
						(
							completeData.forPrint.proxy.useragent.backend
							&& completeData.forPrint.proxy.useragent.frontend
							&& completeData.forPrint.proxy.useragent.backend != completeData.forPrint.proxy.useragent.frontend
						)
						||
						(
							completeData.forPrint.proxy.timezone.backend
							&& completeData.forPrint.proxy.timezone.frontend
							&& completeData.forPrint.proxy.timezone.backend != completeData.forPrint.proxy.timezone.frontend
						)
						||
						(
							completeData.forPrint.proxy.language.backend
							&& completeData.forPrint.proxy.language.frontend
							&& completeData.forPrint.proxy.language.backend != completeData.forPrint.proxy.language.frontend
						)
						||
						(
							completeData.forPrint.proxy.webrtc.ip.length > 0
							&& completeData.forPrint.proxy.webrtc.ip.public != completeData.forPrint.http.ip
						)
						||
						(
							completeData.forPrint.visitor_information.real_ip
							&& completeData.forPrint.visitor_information.real_ip != completeData.forPrint.http.ip
						)
					)
			)
			{
				completeData.forPrint.detected_anonymizers.vpn = true;
			}
		}
	}

	/**
	 * Set platform for compare
	 * @param platform {string}
	 * @returns {string|boolean}
	 */
	function setPlatform(platform) {
		if ( !platform || platform == undefined || platform == '' ) return false;

		platform = platform.toLowerCase();

		if ( platform.indexOf("win") > -1 ) {
			return "Windows";
		} else if ( platform.indexOf("mac") > -1 ) {
			return "Mac";
		} else if ( platform.indexOf("iph") > -1 || platform.indexOf("ios") > -1 ) {
			return "iPhone";
		} else if ( platform.indexOf("lin") > -1 ) {
			return "Linux";
		} else if ( platform.indexOf("and") > -1 ) {
			return "Android";
		}


		return "Other";
	}

	/**
	 * Compare and detect lied platform
	 * @param platformsObject {object}
	 * @returns {boolean}
	 */
	function detectLiedPlatform(platformsObject) {
		let platformsArray = ["Windows","Mac","iPhone","Linux","Android"];

		if
		(
			platformsObject.useragent_backend == platformsObject.useragent_frontend == platformsObject.js == platformsObject.nmap
		)
		{
			return false;
		}

		for ( let i in platformsArray ) {

			if
			(
				platformsObject.useragent_backend == platformsArray[i]
				&&
				(
					(
						platformsObject.useragent_frontend
						&& platformsObject.useragent_frontend != platformsArray[i]
					)
					||
					(
						platformsObject.js
						&& platformsObject.js != platformsArray[i]
					)
					||
					(
						platformsObject.nmap
						&& platformsObject.nmap != platformsArray[i]
					)
				)
			)
			{
				return true;
			} else {
				continue;
			}

		}

		return false;

	}

	/**
	 * If requests not possible, using alternative fingerprint
	 */
	function alternativeFingerprint() {
		completeData.forPrint.vulnerabilities.javascript = true;
		completeData.forPrint.vulnerabilities.cookie = navigator.cookieEnabled;

		if ( completeData.webrtc.ip.public ) {
			completeData.forPrint.visitor_information.real_ip = completeData.webrtc.ip.public;
			completeData.forPrint.vulnerabilities.webrtc = true;
		}

		completeData.forPrint.vulnerabilities.localstorage = localStorage.cookieID
			? localStorage.cookieID.length > 0
			: false;
		completeData.forPrint.vulnerabilities.sessionstorage = sessionStorage.cookieID
			? sessionStorage.cookieID.length > 0
			: false;

		completeData.forPrint.proxy.useragent.frontend = navigator.userAgent;
		completeData.forPrint.proxy.timezone.frontend = Intl.DateTimeFormat().resolvedOptions().timeZone;
		completeData.forPrint.proxy.language.frontend = navigator.languages.slice().sort().join();

		let gl = document.createElement('canvas').getContext('webgl');
		let debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
		let vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
		let renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);

		completeData.forPrint.device_info.js = {
			platform: navigator.platform,
			webgl_vendor_and_renderer: `${vendor} ${renderer}`,
			hardware_concurrency: navigator.hardwareConcurrency,
			device_memory: navigator.deviceMemory,
			screen_resolution: `${window.outerWidth}x${window.outerHeight}`,
			touch_support: {
				maxTouchPoints: navigator.maxTouchPoints
			},
		}

		if
		(
			location.hostname != config.host_url.replace(/(http|https)(:\/\/)([\d\.]+|([\w+\.\w+]+))(\/)?/,"$3")
		)
		{
			completeData.forPrint.proxy.webproxy = true;
		}
	}

}


/** Running inspection **/

document.addEventListener("DOMContentLoaded", app);