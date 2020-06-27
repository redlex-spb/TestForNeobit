const express = require('express');
const router = express.Router();

const whois = require('../lib/whois');

router.get('/', whois.getData);

module.exports = router;