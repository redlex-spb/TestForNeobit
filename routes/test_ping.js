var express = require('express');
var router = express.Router();

var ping = require('../lib/ping');

router.get('/', ping.sendTime);

module.exports = router;