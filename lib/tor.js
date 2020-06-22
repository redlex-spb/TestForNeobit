const debug = require('debug')('fingerprint:tor');
const https = require('https');

const isTor = (req, res) => {
	/** Variable **/

	let clientIP = req.ip.replace("::ffff:",""),
		 linksTorIpDatabases = [
			 "https://check.torproject.org/torbulkexitlist",
			 "https://www.dan.me.uk/torlist/"
		 ]

	linksTorIpDatabases.forEach((link,index)=>{
		https.get(link, (resp) => {
			let data = '';

			resp.on('data', (chunk) => {
				data += chunk;
			});

			resp.on('end', () => {
				if ( data.indexOf(clientIP) > -1 ) {
					if ( req.session.fingerprintArray ) {
						req.session.reload(() => {
							//req.session.fingerprintArray.proxy.tor = true;
							req.session.fingerprintArray.detected_anonymizers.tor = true;
							res.status(200).json({isTor: true});
						});
					} else {
						res.status(200).json({isTor: true});
					}
				}
				if (
					linksTorIpDatabases.length-1 == index
					&& data.indexOf(clientIP) == -1
				) {
					res.status(200).json({isTor: false});
				}
			});

		}).on("error", (err) => {
			console.log("Error: " + err.message);
			res.status(500).end();
		});
	});

	res.setHeader('Content-Type', 'application/json');

}

module.exports = {
	isTor
}