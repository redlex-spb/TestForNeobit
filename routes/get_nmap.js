var express = require('express');
var router = express.Router();

var nmap = require('../lib/nmap');

router.get('/', nmap.getNmapData);

module.exports = router;