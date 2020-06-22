var express = require('express');
var router = express.Router();

var dns = require('../lib/dns');

router.get('/', dns.getHostname);

module.exports = router;