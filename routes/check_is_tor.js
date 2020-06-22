var express = require('express');
var router = express.Router();

var tor = require('../lib/tor');

router.get('/', tor.isTor);

module.exports = router;