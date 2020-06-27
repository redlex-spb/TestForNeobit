const debug = require('debug')('fingerprint:dns');
const dns = require('dns');

const getHostname = (req, res) => {
	/** Variable **/
	let clientIP = req.ip.replace("::ffff:",""),
		 result = "";

	dns.reverse(clientIP, function (err,data) {
		if ( req.session.fingerprintArray ) {

			req.session.reload(() => {
				if ( typeof data == "object" ) {
					for ( let host in data ) {
						if ( result == "" ) result += data[host];
						else result += `, ${data[host]}`;
					}
				}

				req.session.fingerprintArray.proxy.hostname.dns = result;

				if
				(
					result.indexOf("proxy") > -1
					|| result.indexOf("vpn") > -1
					|| result.indexOf("hide") > -1
					|| result.indexOf("hidden") > -1
					|| result.indexOf("tor") > -1
				)
				{
					req.session.fingerprintArray.proxy.suspicious_host = true;
				}

				res.setHeader('Content-Type', 'application/json');
				res.status(200).json(data);
			});

		} else {
			res.status(200).end();
		}
	});
}

module.exports = {
	getHostname
}