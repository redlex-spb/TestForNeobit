const debug = require('debug')('fingerprint:nmap');
const nmap = require('node-nmap');

const getNmapData = (req, res) => {

	nmap.nmapLocation = "nmap";

	/** Variable **/

	let openProxyPorts = false,
		openVPNPorts = false,
		clientIP = req.ip.replace("::ffff:",""),
		quickscan = new nmap.OsAndPortScan(clientIP);
		//quickscan = new nmap.QuickScan(clientIP);

	quickscan.on('complete', function(data){
		//debug("nmapData",data[0]);
		if (
				data[0]
				&& data[0].openPorts
				&& data[0].openPorts.length > 0
		) {
			detectProxy(data[0].openPorts, openProxyPorts, openVPNPorts);
		}

		if ( req.session.fingerprintArray ) {

			req.session.reload(() => {

				if ( data[0] && data[0].hostname ) {
					if
					(
						data[0].hostname.indexOf("proxy") > -1
						|| data[0].hostname.indexOf("vpn") > -1
						|| data[0].hostname.indexOf("hide") > -1
						|| data[0].hostname.indexOf("hidden") > -1
						|| data[0].hostname.indexOf("tor") > -1
					)
					{
						req.session.fingerprintArray.proxy.suspicious_host = true;
					}
				}

				req.session.fingerprintArray.nmap = {
					data: data[0] || {},
					open_proxy_ports: openProxyPorts,
					open_vpn_ports: openVPNPorts
				};

				res.setHeader('Content-Type', 'application/json');
				res.status(200).json(
					{
						nmap_data: data[0] || {},
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

	for ( let i in openPorts ) {
		if ( openPorts[i].service == 'http-proxy' ) {
			openProxyPorts = true;
		}
		if
		(
			openPorts[i].service == 'pptp'
			|| openPorts[i].service == 'radan-http'
			|| openPorts[i].service == 'isakmp' // IPSec
			|| openPorts[i].service == 'ipsec-nat-t'
			|| openPorts[i].service == 'openvpn'
			|| openPorts[i].service == 'l2tp'
			|| openPorts[i].service == 'vpnz'
			|| openPorts[i].service == 'pit-vpn'
			|| openPorts[i].service == 'escvpnet'
			|| openPorts[i].service == 'apple-vpns-rp'
			|| openPorts[i].service == 'ghvpn'
			|| openPorts[i].service == 'amicon-fpsu-s'
			|| openPorts[i].port == '47' // pptp
		)
		{
			openVPNPorts = true;
		}
	}

}

module.exports = {
	getNmapData
}