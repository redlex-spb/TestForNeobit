var express = require('express');
var router = express.Router();

var fingerprint = require('../lib/fingerprint');

router.get('/', fingerprint.buildBackendFingerprint);
router.post('/', fingerprint.addFrontendFingerprint);

module.exports = router;
