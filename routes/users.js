var express = require('express');
var router = express.Router();

const db = require('../lib/db');

/* GET users listing. */
router.get('/', function(req, res, next) {

  db.getUsers().then(result => {
    res.render('users', { data: result });
  });

});

module.exports = router;
