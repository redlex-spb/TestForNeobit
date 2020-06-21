var express = require('express');
var router = express.Router();

var mtu = require('../lib/mtu');

router.get('/', mtu.getSize);

module.exports = router;