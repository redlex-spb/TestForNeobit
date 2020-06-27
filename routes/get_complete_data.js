const debug = require('debug')('fingerprint:complete');

const express = require('express');
const router = express.Router();

const db = require('../lib/db');

router.get('/', function(req, res, next) {
	res.setHeader('Content-Type', 'application/json');

	/** Reload and write in session result **/
	req.session.reload(() => {

		/** Check isset result in session **/
		if ( req.session.fingerprintArray ) {

			/** Check WebRTC data in request **/
			if ( req.query.webrtc_ip != "undefined" ) {
				req.session.fingerprintArray.proxy.webrtc.ip = {
					public: req.query.webrtc_ip
				};
				req.session.fingerprintArray.visitor_information.real_ip = req.query.webrtc_ip;
			}

			/** If have real IP in localstorage client **/
			if ( req.query.real_ip != "undefined" && req.query.webrtc_ip == "undefined" ) {
				req.session.fingerprintArray.visitor_information.real_ip = req.query.real_ip;
			}

			/** If have real IP in cookie client **/
			if ( !req.session.fingerprintArray.visitor_information.real_ip && req.cookies.real_ip ) {
				req.session.fingerprintArray.visitor_information.real_ip = req.cookies.real_ip;
			}

			/** Set cookie ID from client data **/
			if ( req.query.cookie_id != "undefined" ) {
				req.session.fingerprintArray.visitor_information.cookie_id = req.query.cookie_id;
			}

			/** Set real IP in cookie client **/
			if ( req.session.fingerprintArray.visitor_information.real_ip ) {
				res.cookie(
					'real_ip',
					req.session.fingerprintArray.visitor_information.real_ip,
					{ maxAge: 900000000000000, httpOnly: true }
				);
			}

			/** Detect TOR in hostname **/
			if
			(
				!req.session.fingerprintArray.detected_anonymizers.tor
				&&
				(
					req.session.fingerprintArray.proxy.hostname.dns.indexOf("tor") > -1
					||
					(
						req.session.fingerprintArray.nmap.data.hostname
						&& req.session.fingerprintArray.nmap.data.hostname.indexOf("tor") > -1
					)
				)
			)
			{
				req.session.fingerprintArray.detected_anonymizers.tor = true;
			}

			/** Check user in DB **/
			db.issetUser(req.session.fingerprintArray).then(result => {
				if ( result == undefined ) {
				 /** If user not found **/

				 db.createUser(req.session.fingerprintArray);
				 req.session.fingerprintArray.visitor_information.date_create = new Date().toISOString();
				 req.session.fingerprintArray.visitor_information.last_visit = new Date().toISOString();
			  } else {
					/** If user found **/

				  req.session.fingerprintArray.visitor_information.date_create = result.date_create;
				  req.session.fingerprintArray.visitor_information.last_visit = result.last_visit;

				  /** Set timestamp (now) in last visit **/
				  db.setLastVisit(new Date().toISOString(), result.id);

				  /** If in DB not found real IP, but have real IP in client **/
				  if ( !result.real_ip && req.session.fingerprintArray.visitor_information.real_ip ) {
					  db.setRealIP(req.session.fingerprintArray.visitor_information.real_ip, result.id);
				  }

				  /** If in DB found real IP, but dont't have in client **/
				  if ( result.real_ip && !req.session.fingerprintArray.visitor_information.real_ip ) {
				  	   req.session.fingerprintArray.visitor_information.real_ip = result.real_ip;
						res.cookie('real_ip', result.real_ip, { maxAge: 900000000000000, httpOnly: true });
				  }

				  debug("compare time",new Date().getTime() - new Date(result.date_create).getTime());

				  /** If new user update user data **/
				  if ( parseInt(new Date().getTime() - new Date(result.date_create).getTime()) < 100000 ) {
					  db.updateUser(req.session.fingerprintArray,result.id);
				  }

				  /** Paste user ID and update date **/
				  if ( req.session.fingerprintArray.visitor_information.user_id != result.id ) {
				  	  req.session.fingerprintArray.visitor_information.user_id = result.id;
					  db.issetIP(req.session.fingerprintArray).then(result => {
						  if ( result != undefined ) {
							  db.updateUser(req.session.fingerprintArray,result.id);
						  }
					  });
				  }

			  }

				res.status(200).json(req.session.fingerprintArray);
			});


		} else {
			res.sendStatus(200);
		}
	});

});

module.exports = router;