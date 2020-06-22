var express = require('express');
var router = express.Router();

const db = require('../lib/db');

router.get('/', function(req, res, next) {
	res.setHeader('Content-Type', 'application/json');

	req.session.reload(() => {
		if ( req.session.fingerprintArray ) {

			if ( req.query.webrtc_ip ) {
				req.session.fingerprintArray.proxy.webrtc.ip = req.query.webrtc_ip;
			}

			if ( req.query.cookie_id ) {
				req.session.fingerprintArray.visitor_information.cookie_id = req.query.cookie_id;
			}

			db.issetUser(req.session.fingerprintArray).then(result => {
				if ( result == undefined ) {
				 req.session.fingerprintArray.hash = req.body.hash;
				 db.createUser(req.session.fingerprintArray);
				  req.session.fingerprintArray.visitor_information.data_create = new Date().toISOString();
				  req.session.fingerprintArray.visitor_information.last_visit = new Date().toISOString();
			  } else {
				  req.session.fingerprintArray.visitor_information.data_create = new Date(result.date_create).toLocaleString();
				  req.session.fingerprintArray.visitor_information.last_visit = new Date(result.last_visit).toLocaleString();

				  db.setLastVisit(new Date().toISOString(), result.id);
			  }

				res.status(200).json(req.session.fingerprintArray);
			});


		} else {
			res.sendStatus(200);
		}
	});

});

module.exports = router;