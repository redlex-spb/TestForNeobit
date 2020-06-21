var express = require('express');
var router = express.Router();

var whois = require('../lib/whois');

router.get('/', whois.getData);

module.exports = router;