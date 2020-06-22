var debug = require('debug')('fingerprint:whois');
var whois = require('whois');

const getData = (req, res) => {
	/** Variable **/

	let clientIP = req.ip.replace("::ffff:","");

	whois.lookup(clientIP, function (err,data) {
		if ( req.session.fingerprintArray ) {

			req.session.reload(() => {
				req.session.fingerprintArray.whois = data;

				res.setHeader('Content-Type', 'application/json');
				res.status(200).json(data);
			});

		} else {
			res.status(200).end();
		}
	});
}

module.exports = {
	getData
}