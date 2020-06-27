const express = require('express');
const router = express.Router();

const nmap = require('../lib/nmap');

router.get('/', nmap.getNmapData);

module.exports = router;