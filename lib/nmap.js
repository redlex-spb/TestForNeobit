var debug = require('debug')('fingerprint:nmap');
var nmap = require('node-nmap');

const getNmapData = (req, res) => {
	/** Variable **/

	let openProxyPorts = false,
		openVPNPorts = false,
		clientIP = req.ip.replace("::ffff:",""),
		quickscan = new nmap.OsAndPortScan(clientIP);

	nmap.nmapLocation = "nmap";

	quickscan.on('complete', function(data){
		//debug("nmapData",data[0]);
		detectProxy(data[0].openPorts, openProxyPorts, openVPNPorts);
		if ( req.session.fingerprintArray ) {

			req.session.reload(() => {
				req.session.fingerprintArray.nmap = {
					data: data[0],
					open_proxy_ports: openProxyPorts,
					open_vpn_ports: openVPNPorts
				};

				res.setHeader('Content-Type', 'application/json');
				res.status(200).json(
					{
						nmap_data: data[0],
						open_proxy_ports: openProxyPorts,
						open_vpn_ports: openVPNPorts
					}
				);
			});

		} else {
			res.status(200).end();
		}
	});

	quickscan.on('error', function(error){
		res.status(500).end(error);
	});

	quickscan.startScan();

}

function detectProxy(openPorts, openProxyPorts, openVPNPorts) {

	openPorts.forEach(function (element) {
		if ( element.service == 'http-proxy' ) {
			openProxyPorts = true;
		}
		if
		(
			element.service == 'pptp'
			|| element.service == 'radan-http'
			|| element.service == 'isakmp' // IPSec
			|| element.service == 'ipsec-nat-t'
			|| element.service == 'openvpn'
			|| element.service == 'l2tp'
			|| element.service == 'vpnz'
			|| element.service == 'pit-vpn'
			|| element.service == 'escvpnet'
			|| element.service == 'apple-vpns-rp'
			|| element.service == 'ghvpn'
			|| element.service == 'amicon-fpsu-s'
			|| element.port == '47' // pptp
		)
		{
			openVPNPorts = true;
		}
	});

}

module.exports = {
	getNmapData
}