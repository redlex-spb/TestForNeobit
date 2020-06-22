const debug = require('debug')('fingerprint:app');

const md5 = require('md5');
const geoip = require('geoip-lite');
const useragent = require('useragent');

//const db = require('./db');


const buildBackendFingerprint = (req, res) => {
	/** Variable **/

	let clientIP = req.ip.replace("::ffff:","");


	/** Cookie **/

	let cookie_id = req.cookies.id;

	if ( cookie_id === undefined ) {
		cookie_id = md5(Date.now() + req.ip);
		res.cookie('id', cookie_id, { maxAge: 900000000000000, httpOnly: true });
	}


	/** Geo info **/

	let geo = geoip.lookup(clientIP);


	/** Detect Proxy headers **/

	let proxy_headers = false;

	if
	(
		//req.headers.referer != undefined
		req.headers['x-forwarded-for'] != undefined
		|| req.headers['forwarded'] != undefined
		|| req.headers['x-forwarded-host'] != undefined
		|| req.headers['x-forwarded-proto'] != undefined
		|| req.headers['x-forwarded-for'] != undefined
		|| req.headers['x-proxy-id'] != undefined
		|| req.headers['x-real-ip'] != undefined
		|| req.headers['via'] != undefined
	)
	{
		proxy_headers = true;
	}


	/** Parse User-Agent **/

	let agent = useragent.parse(req.headers['user-agent']);


	/** Generate hash **/

	let hashArray = [
		clientIP,
		agent.toAgent(),
		agent.os.toString(),
		agent.device.toString(),
		cookie_id,
		req.sessionID || req.session.id,
		geo.timezone,
		req.headers['accept-language']
	];

	let hashSumm = md5(hashArray + Math.random());

	let fingerprintArray = {
		detected_anonymizers: {
			proxy: false,
			vpn: false,
			tor: false
		},
		vulnerabilities: {
			javascript: false,
			webrtc : false,
			flash: false,
			cookie: false,
			localstorage: false,
			sessionstorage: false
		},
		visitor_information: {
			hash: {
				backend: hashSumm,
				frontend: "",
			},
			cookie_id: cookie_id,
			session_id: req.sessionID || req.session.id,
			data_create: "",
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
			useragent: {
				backend:  req.headers['user-agent'],
				frontend: "",
			},
			timezone: {
				backend: geo.timezone,
				frontend: "",
			},
			language: {
				backend: req.headers['accept-language'],
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
		nmap: {},
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

	//debug('fingerprintArray',fingerprintArray);

	req.session.fingerprintArray = fingerprintArray;
	res.render('index', { data: fingerprintArray });
}

const addFrontendFingerprint = (req, res) => {

	res.setHeader('id', req.cookies.id);

	if ( req.session.fingerprintArray ) {

		/** Parse User-Agent **/

		let agent = useragent.parse(req.body.res.userAgent);


		/** Generate hash **/

		let hashArray = [
			agent.toAgent(),
			agent.os.toString(),
			agent.device.toString(),
			req.cookies.id,
			req.sessionID || req.session.id,
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

		let hashSumm = md5(hashArray + Math.random());

		req.session.reload(() => {



			req.session.fingerprintArray.vulnerabilities.cookie = true;
			req.session.fingerprintArray.vulnerabilities.localstorage = req.body.res.localStorage;
			req.session.fingerprintArray.vulnerabilities.sessionstorage = req.body.res.sessionStorage;

			//req.session.fingerprintArray.visitor_information.cookie_id = req.body.res.cookie_id;

			req.session.fingerprintArray.proxy.useragent.frontend = req.body.res.userAgent;
			req.session.fingerprintArray.proxy.timezone.frontend = req.body.res.timezone;
			req.session.fingerprintArray.proxy.language.frontend = req.body.res.language;

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
				cpu_class: req.body.res.cpu_class != "not available" ? req.body.res.cpu_class : "-",
				webgl_vendor_and_renderer: req.body.res.webglVendorAndRenderer,
				hardware_concurrency: req.body.res.hardwareConcurrency,
				device_memory: req.body.res.deviceMemory != "not available" ? `${req.body.res.deviceMemory} Gb` : "-",
				screen_resolution: `${req.body.res.screenResolution[0]}x${req.body.res.screenResolution[1]}`,
				color_depth: req.body.res.colorDepth,
				touch_support: {
					maxTouchPoints: req.body.res.touchSupport[0],
					touchEvent: req.body.res.touchSupport[1],
					touchStart: req.body.res.touchSupport[2]
				},
				using_adblock: req.body.res.adBlock,
			}
			req.session.fingerprintArray.visitor_information.hash.frontend = hashSumm;

			res.setHeader('Content-Type', 'application/json');
			res.status(200).json({status: "success"});

		});
	}
}

module.exports = {
	buildBackendFingerprint,
	addFrontendFingerprint
}