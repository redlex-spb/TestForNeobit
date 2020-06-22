const debug = require('debug')('fingerprint:ping');
const performance = require('perf_hooks').performance;

const sendTime = (req, res) => {
	res.setHeader('Content-Type', 'application/json');
	res.status(200).json({time: Date.now()});
}

module.exports = {
	sendTime
}