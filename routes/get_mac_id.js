var express = require('express');
var router = express.Router();

var arp = require('../lib/arp');

router.get('/', arp.getMacID);

module.exports = router;