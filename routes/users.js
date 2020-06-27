const express = require('express');
const router = express.Router();

const db = require('../lib/db');

router.get('/', function(req, res, next) {

  db.getUsers().then(result => {
    res.render('users', { data: result });
  });

});

module.exports = router;