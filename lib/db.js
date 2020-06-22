const debug = require('debug')('fingerprint:db');
const Pool = require('pg').Pool
const pool = new Pool({
	user: 'user',
	host: 'localhost',
	database: 'db',
	password: 'password',
	port: 5432,
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
			`select id, date_create, last_visit from users where ip = $1 or hash_frontend like $2 or hash_backend like $3 or cookie_id like $4 or session_id like $5 /*or TEXT(webrtc) = $6  or mac like $7*/;`,
			[
				data.http.ip,
				data.visitor_information.hash.frontend,
				data.visitor_information.hash.backend,
				data.visitor_information.cookie_id,
				data.visitor_information.session_id,
				//data.proxy.webrtc,
				//data.device_info.arp || data.nmap.mac,
			]
		);
		return res.rows[0];
	} catch (err) {
		return err.stack;
	}
}

const createUser = (data) => {
	pool.query(
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
			'last_visit' +
		') ' +
		'VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26)',
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

			new Date().toISOString()
		],
		(error, result) => {
			if (error) {
				//throw error
				debug(error);
			} else {
				debug(`User added with IP: ${data.http.ip}`);
			}
		}
	)
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

module.exports = {
	getUsers,
	issetIP,
	issetUser,
	createUser,
	setLastVisit
}