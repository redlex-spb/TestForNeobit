var debug = require('debug')('fingerprint:dns');
var ping = require('ping');

const getSize = (req, res) => {
	/** Variable **/

	let clientIP = req.ip.replace("::ffff:",""),
	    MTUSizes = [1472,1407,1313,1125,750,32],
	    clientMTU;

	MTUSizes.forEach(function(MTUSize){
		ping.promise.probe(clientIP, {
			timeout: 10,
			extra: ['-f', '-l', MTUSize],
		}).then(function (res) {
			if
			(
				res.alive === true
				&& req.session.fingerprintArray
			)
			{
				req.session.reload(() => {
					//req.session.fingerprintArray.mtu = MTUSize;
					req.session.fingerprintArray.proxy.mtu = MTUSize;

					res.setHeader('Content-Type', 'application/json');
					res.status(200).json(MTUSize);
				});

			} else {
				res.status(200).json({});
			}
		}).catch(function () {
			res.status(500).json({});
		});
	});

}

module.exports = {
	getSize
}