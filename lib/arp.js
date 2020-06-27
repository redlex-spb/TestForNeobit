const debug = require('debug')('fingerprint:arp');
const arp = require('node-arp');

const getMacID = (req, res) => {
	/** Variable **/
	let clientIP = req.ip.replace("::ffff:","");

	arp.getMAC(clientIP, function (err,data) {
		if (err) {
			res.sendStatus(500);
		} else {
			if ( req.session.fingerprintArray ) {
				req.session.reload(() => {
					req.session.fingerprintArray.device_info.arp = {macID: data};

					res.setHeader('Content-Type', 'application/json');
					res.status(200).json(data || {});
				});

			} else {
				res.sendStatus(200);
			}
		}
	});
}

module.exports = {
	getMacID
}