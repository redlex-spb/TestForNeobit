const express = require('express');
const router = express.Router();

const dns = require('../lib/dns');

router.get('/', dns.getHostname);

module.exports = router;