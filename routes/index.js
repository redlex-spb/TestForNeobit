const express = require('express');
const router = express.Router();

const fingerprint = require('../lib/fingerprint');

router.get('/', fingerprint.buildBackendFingerprint);
router.post('/', fingerprint.addFrontendFingerprint);

module.exports = router;
