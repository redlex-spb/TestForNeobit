const express = require('express');
const router = express.Router();

const tor = require('../lib/tor');

router.get('/', tor.isTor);

module.exports = router;