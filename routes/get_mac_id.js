const express = require('express');
const router = express.Router();

const arp = require('../lib/arp');

router.get('/', arp.getMacID);

module.exports = router;