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

			db.issetUser(req.session.fingerprintArray).then(result => {
			  //debug('result',result);
			  if ( result == undefined ) {
				 req.session.fingerprintArray.hash = req.body.hash;
				 db.createUser(req.session.fingerprintArray);
				  req.session.fingerprintArray.visitor_information.data_create = new Date().toISOString();
				  req.session.fingerprintArray.visitor_information.last_visit = new Date().toISOString();
			  } else {
				  req.session.fingerprintArray.visitor_information.data_create = result.data_create;
				  req.session.fingerprintArray.visitor_information.last_visit = result.last_visit;

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