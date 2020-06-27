const express = require('express');
const router = express.Router();

const mtu = require('../lib/mtu');

router.get('/', mtu.getSize);

module.exports = router;