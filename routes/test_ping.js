const express = require('express');
const router = express.Router();

const ping = require('../lib/ping');

router.get('/', ping.sendTime);

module.exports = router;