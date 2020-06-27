const debug = require('debug')('fingerprint:app');

const crypto = require('crypto');
const geoip = require('geoip-lite');
const useragent = require('useragent');
const fs = require('fs');

const config = require('../config/config');
const db = require('./db');


const buildBackendFingerprint = (req, res) => {
	/** Variable **/

	let clientIP = req.ip.replace("::ffff:",""),
		realIP = "",
		ip_regex = /([0-9]{1,3}(\.[0-9]{1,3}){3})/,
		ip_regex_exec;


	/** Cookie **/

	let cookie_id = req.cookies.id;

	if
	(
		cookie_id === undefined
		|| cookie_id == "undefined"
	) {
		cookie_id = crypto.createHash('sha1').update(req.ip).digest('hex');
		res.cookie('id', cookie_id, { maxAge: 900000000000000, httpOnly: true });
	}


	/** Geo info **/
	let geo = geoip.lookup(clientIP);


	/** Detect Proxy headers **/

	let proxy_headers = false;

	let array_proxy_headers = [
		'forwarded',
		'forwarded-for',
		'forwarded-for-ip',
		'x-forwarded',
		'x-forwarded-for',
		'x-forwarded-for-ip',
		'x-forwarded-host',
		'x-forwarded-proto',
		'x-proxy-id',
		'x-real-ip',
		'via',
		'http-via',
		'http-forwarded',
		'http-forwarded-for',
		'http-forwarded-for-ip',
		'http-x-forwarded',
		'http-x-forwarded-for',
		'http-x-forwarded-for-ip',
		'http-client-ip',
		'client-ip',
		'http-proxy-connection',
	];

	for ( let i in array_proxy_headers  ) {
		if ( req.headers[array_proxy_headers[i]] ) proxy_headers = true;
		ip_regex_exec = ip_regex.exec(req.headers[array_proxy_headers[i]]);
		if ( ip_regex_exec && ip_regex_exec.length > 1 ) {
			if (/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ip_regex_exec[1])){
				realIP = [ip_regex_exec[1]];
				debug("realIP",realIP);
			}
		}
	}


	/** Parse User-Agent **/
	let agent = useragent.parse(req.headers['user-agent']),
		 accept_language;
	if ( req.headers['accept-language'] ) {
		accept_language = req.headers['accept-language']
			.replace(/(\;)?(q\=\d\.\d(\,)?)([(\w+|\d+|\,|\-)]+)?(\;)?/g,",$4")
			.split(",")
			.sort()
			.join(",");
		if ( accept_language.substr(-1) == "," ) accept_language = accept_language.slice(0,-1);
		if ( accept_language.substr(0,1) == "," ) accept_language = accept_language.slice(1);
	}


	/** Generate hash **/

	let hashArray = [
		//clientIP,
		agent.toAgent(),
		agent.os.toString(),
		agent.device.toString(),
		//cookie_id,
		//req.sessionID || req.session.id,
		geo.timezone,
		req.headers['accept-language']
	];

	let hashSumm = crypto.createHash('sha1').update(JSON.stringify(hashArray)).digest('hex');

	/** Detect Tor **/

	let isTor = false;

	fs.readFile('/var/www/html/fingerprint/db/tor.txt', 'utf8', function(err, contents) {
		if ( contents.indexOf(clientIP) > -1 ) {
			isTor = true;
		}
	});


	/** Check user in db **/

	let data = {
		http: {ip: clientIP},
		visitor_information: {
			hash: {
				backend: hashSumm,
				frontend: ""
			},
			cookie_id: cookie_id,
			session_id: req.sessionID || req.session.id
		}
	};

	db.issetUser(data).then(result => {

		let user = result || {};

		/** Collect result **/

		let fingerprintArray = {
			detected_anonymizers: {
				proxy: proxy_headers,
				vpn: false,
				tor: isTor
			},
			vulnerabilities: {
				javascript: false,
				webrtc : false,
				flash: false,
				cookie: false,
				localstorage: false,
				sessionstorage: false,
				donottrack: req.headers.dnt || false
			},
			visitor_information: {
				user_id: user.id || "new",
				real_ip: realIP,
				hash: {
					backend: hashSumm,
					frontend: "",
				},
				cookie_id: cookie_id,
				session_id: req.sessionID || req.session.id,
				date_create: "",
				last_visit: ""
			},
			http: {
				ip: clientIP,
				geo: {
					country: geo.country,
					region: geo.region,
					city: geo.city,
					ll: `${geo.ll[0]},${geo.ll[1]}`
				},
				headers: req.headers,
			},
			proxy: {
				proxy_headers: proxy_headers,
				webproxy: false,
				useragent: {
					backend:  req.headers['user-agent'],
					frontend: "",
				},
				timezone: {
					backend: geo.timezone,
					frontend: "",
				},
				language: {
					backend: accept_language,//req.headers['accept-language'],
					frontend: "",
				},
				hostname: {},
				//tor: "",
				webrtc: {
					ip: ""
				},
				ping: "",
				mtu: ""
			},
			nmap: {
				data: {},
				open_proxy_ports: "",
				open_vpn_ports: ""
			},
			device_info: {
				useragent: {
					backend: {
						browser: agent.toAgent(),
						os: agent.os.toString(),
						device: agent.device.toString(),
					},
					frontend: {
						browser: "",
						os: "",
						device: "",
					},
				},
				arp: {}
			},
		};

		/** Create user **/
		if ( result == undefined ) {
			db.createUser(fingerprintArray);
			fingerprintArray.visitor_information.date_create = new Date().toISOString();
			fingerprintArray.visitor_information.last_visit = new Date().toISOString();
		} else {
			db.setLastVisit(new Date().toISOString(), user.id);
			fingerprintArray.visitor_information.date_create = user.date_create ? user.date_create.toUTCString() : "";
			fingerprintArray.visitor_information.last_visit = user.last_visit ? user.last_visit.toUTCString() : "";
		}


		//debug('fingerprintArray',fingerprintArray);

		/** Save data in session **/
		req.session.fingerprintArray = fingerprintArray;

		/** Rendering page **/
		res.render('index', { data: fingerprintArray, config: config.frontend });

	});

}


const addFrontendFingerprint = (req, res) => {

	/** Check backend fingerprint **/

	if ( req.session.fingerprintArray ) {

		/** Parse User-Agent **/
		let agent = useragent.parse(req.body.res.userAgent);


		/** Generate hash **/

		let hashArray = [
			agent.toAgent(),
			agent.os.toString(),
			agent.device.toString(),
			//req.cookies.id,
			//req.sessionID || req.session.id,
			req.body.res.timezone,
			req.body.res.language,
			req.body.res.webdriver,
			req.body.res.colorDepth,
			req.body.res.deviceMemory,
			req.body.res.hardwareConcurrency,
			req.body.res.screenResolution,
			req.body.res.cpuClass,
			req.body.res.platform,
			req.body.res.plugins,
			req.body.res.webglVendorAndRenderer,
			req.body.res.touchSupport,
			req.body.res.fonts,
			req.body.res.audio
		];

		let hashSumm = crypto.createHash('sha1').update(JSON.stringify(hashArray)).digest('hex');

		/** Reload and write in session result **/

		req.session.reload(() => {

			req.session.fingerprintArray.vulnerabilities.javascript = true;
			req.session.fingerprintArray.vulnerabilities.cookie = req.body.res.cookieEnabled;
			req.session.fingerprintArray.vulnerabilities.localstorage = req.body.res.localStorage;
			req.session.fingerprintArray.vulnerabilities.sessionstorage = req.body.res.sessionStorage;
			req.session.fingerprintArray.vulnerabilities.donottrack = req.body.res.doNotTrack;

			req.session.fingerprintArray.proxy.useragent.frontend = req.body.res.userAgent;
			req.session.fingerprintArray.proxy.timezone.frontend = req.body.res.timezone;
			req.session.fingerprintArray.proxy.language.frontend = req.body.res.languages;
			req.session.fingerprintArray.proxy.webproxy = req.body.res.webproxy || false;

			req.session.fingerprintArray.proxy.lied_os = req.body.res.hasLiedOs;
			req.session.fingerprintArray.proxy.lied_browser = req.body.res.hasLiedBrowser;
			req.session.fingerprintArray.proxy.lied_resolution = req.body.res.hasLiedResolution;
			req.session.fingerprintArray.proxy.lied_languages = req.body.res.hasLiedLanguages;

			req.session.fingerprintArray.device_info.useragent.frontend = {
				browser: agent.toAgent(),
				os: agent.os.toString(),
				device: agent.device.toString(),
			};

			req.session.fingerprintArray.device_info.js = {
				platform: req.body.res.platform,
				cpu_class: req.body.res.cpu_class != "not available"
					? req.body.res.cpu_class
					: "-",
				webgl_vendor_and_renderer: req.body.res.webglVendorAndRenderer,
				hardware_concurrency: req.body.res.hardwareConcurrency != "not available"
					? req.body.res.hardwareConcurrency
					: "-",
				device_memory: req.body.res.deviceMemory && req.body.res.deviceMemory != "not available"
					? `${req.body.res.deviceMemory} Gb`
					: "-",
				screen_resolution: req.body.res.screenResolution
					? `${req.body.res.screenResolution[0]}x${req.body.res.screenResolution[1]}`
					: "-",
				color_depth: req.body.res.colorDepth,
				touch_support: req.body.res.touchSupport
					? {
						maxTouchPoints: req.body.res.touchSupport[0],
						touchEvent: req.body.res.touchSupport[1],
						touchStart: req.body.res.touchSupport[2]
					}
					: "-",
				using_adblock: req.body.res.adBlock,
			}
			req.session.fingerprintArray.visitor_information.hash.frontend = hashSumm;

			/** Send result and set content type **/
			res.setHeader('Content-Type', 'application/json');
			res.status(200).json({status: "success"});

		});
	}
}

module.exports = {
	buildBackendFingerprint,
	addFrontendFingerprint
}