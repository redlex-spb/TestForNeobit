const debug = require('debug')('fingerprint:db');
const Pool = require('pg').Pool
const config = require('../config/config').backend.db;
const pool = new Pool({
	user: config.user,
	host: config.host,
	database: config.database,
	password: config.password,
	port: config.port
})

const getUsers = async () => {
	try {
		const res = await pool.query(
			'SELECT * FROM users ORDER BY id ASC'
		);
		return res.rows;
	} catch (err) {
		return err.stack;
	}
}

const issetIP = async (data) => {
	try {
		const res = await pool.query(
			`SELECT * FROM users WHERE ip=$1`, [data.http.ip]
		);
		return res.rows[0];
	} catch (err) {
		return err.stack;
	}
}

const issetUser = async (data) => {
	try {
		const res = await pool.query(
			`SELECT id, date_create, last_visit, real_ip `+
			`FROM users `+
			`WHERE `+
				`ip = $1 `+
				`OR (hash_frontend LIKE $2 AND hash_frontend != '') `+
				`OR hash_backend LIKE $3 `+
				`OR cookie_id LIKE $4 `+
				`OR session_id LIKE $5 `+
				`OR (real_ip != '' AND real_ip LIKE $6) `+
				//`OR TEXT(webrtc) = $7  `+
				//`OR mac like $8`+
			` ORDER BY id;`,
			[
				data.http.ip,
				data.visitor_information.hash.frontend,
				data.visitor_information.hash.backend,
				data.visitor_information.cookie_id,
				data.visitor_information.session_id,
				data.visitor_information.real_ip,
				//data.proxy.webrtc,
				//data.device_info.arp || data.nmap.mac,
			]
		);
		return res.rows[0];
	} catch (err) {
		return err.stack;
	}
}

const createUser = async (data) => {
	try {
		const res = await pool.query(
			'INSERT INTO users ' +
			'(' +
				'ip, ' +
				'useragent_backend, ' +
				'useragent_frontend, ' +
				'browser_backend, ' +
				'browser_frontend, ' +

				'os_backend, ' +
				'os_frontend, ' +
				'device_backend, ' +
				'device_frontend, ' +
				'hash_backend, ' +

				'hash_frontend, ' +
				'cookie_id, ' +
				'session_id, ' +
				'geo_backend, ' +
				'timezone_backend, ' +

				'timezone_frontend, ' +
				'dns_backend, ' +
				'dns_frontend, ' +
				'webrtc, ' +
				'mtu, ' +

				'language_backend, ' +
				'language_frontend, ' +
				'headers, ' +
				'mac, ' +
				'nmap,' +

				'last_visit,' +
				'real_ip' +
			') ' +
			'VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27)',
			[
				data.http.ip,
				data.proxy.useragent.backend,
				data.proxy.useragent.frontend,
				data.device_info.useragent.backend.browser,
				data.device_info.useragent.frontend.browser,

				data.device_info.useragent.backend.os,
				data.device_info.useragent.frontend.os,
				data.device_info.useragent.backend.device,
				data.device_info.useragent.frontend.device,
				data.visitor_information.hash.backend,

				data.visitor_information.hash.frontend,
				data.visitor_information.cookie_id,
				data.visitor_information.session_id,
				data.http.geo,
				data.proxy.timezone.backend,

				data.proxy.timezone.frontend,
				data.proxy.hostname.dns,
				data.dns_frontend,
				data.proxy.webrtc,
				data.proxy.mtu || 0,

				data.proxy.language.backend,
				data.proxy.language.frontend,
				data.http.headers,
				data.device_info.arp,
				data.nmap,

				new Date().toISOString(),
				data.visitor_information.real_ip
			],
			(error, result) => {
				if (error) {
					//throw error
					debug(error);
				} else {
					debug(`User added with IP: ${data.http.ip}`);
				}
			}
		);

		return res;
	} catch (err) {
		return err.stack;
	}
}

const setLastVisit = async (time,id) => {
	pool.query(
		'UPDATE users SET last_visit = $1 WHERE id = $2',
		[time, id],
		(error, results) => {
			if (error) {
				//throw error
				debug(error);
			}
		}
	)
}

const setRealIP = async (ip,id) => {
	pool.query(
		'UPDATE users SET real_ip = $1 WHERE id = $2',
		[ip, id],
		(error, results) => {
			if (error) {
				//throw error
				debug(error);
			}
		}
	)
}

const updateUser = async (data,id) => {
	pool.query(
		'UPDATE users ' +
		'SET ' +
			//'ip = $2, ' +
			'useragent_backend = $2, ' +
			'useragent_frontend = $3, ' +
			'browser_backend = $4, ' +
			'browser_frontend = $5, ' +

			'os_backend = $6, ' +
			'os_frontend = $7, ' +
			'device_backend = $8, ' +
			'device_frontend = $9, ' +
			'hash_backend = $10, ' +

			'hash_frontend = $11, ' +
			'cookie_id = $12, ' +
			'session_id = $13, ' +
			'geo_backend = $14, ' +
			'timezone_backend = $15, ' +

			'timezone_frontend = $16, ' +
			'dns_backend = $17, ' +
			'dns_frontend = $18, ' +
			'webrtc = $19, ' +
			'mtu = $20, ' +

			'language_backend = $21, ' +
			'language_frontend = $22, ' +
			'headers = $23, ' +
			'mac = $24, ' +
			'nmap = $25,' +

			'last_visit = $26,' +
			'real_ip = $27' +
		' WHERE id = $1',
		[
			id,
			//data.http.ip,
			data.proxy.useragent.backend,
			data.proxy.useragent.frontend,
			data.device_info.useragent.backend.browser,
			data.device_info.useragent.frontend.browser,

			data.device_info.useragent.backend.os,
			data.device_info.useragent.frontend.os,
			data.device_info.useragent.backend.device,
			data.device_info.useragent.frontend.device,
			data.visitor_information.hash.backend,

			data.visitor_information.hash.frontend,
			data.visitor_information.cookie_id,
			data.visitor_information.session_id,
			data.http.geo,
			data.proxy.timezone.backend,

			data.proxy.timezone.frontend,
			data.proxy.hostname.dns,
			data.dns_frontend,
			data.proxy.webrtc,
			data.proxy.mtu || 0,

			data.proxy.language.backend,
			data.proxy.language.frontend,
			data.http.headers,
			data.device_info.arp,
			data.nmap,

			new Date().toISOString(),
			data.visitor_information.real_ip
		],
		(error, results) => {
			if (error) {
				//throw error
				debug(error);
			}
		}
	)
}

module.exports = {
	getUsers,
	issetIP,
	issetUser,
	createUser,
	setLastVisit,
	setRealIP,
	updateUser
}