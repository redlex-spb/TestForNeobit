const createError = require('http-errors');
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const redis   = require("redis");
const redisStore = require('connect-redis')(session);
const logger = require('morgan');

const indexRouter = require('./routes/index');
const usersRouter = require('./routes/users');
const getNmapRouter = require('./routes/get_nmap');
const getHostname = require('./routes/get_hostname');
const getWhois = require('./routes/get_whois');
const getMacID = require('./routes/get_mac_id');
const getMTUSize = require('./routes/get_mtu_size');
const getCompleteData = require('./routes/get_complete_data');
const checkIsTor = require('./routes/check_is_tor');
const testPing = require('./routes/test_ping');

const app = express();
const client  = redis.createClient();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser('neobit'));
app.use(express.static(path.join(__dirname, 'public')));

app.use(
   session({
     secret: 'neobit',
     store: new redisStore({ host: 'localhost', port: 6379, client: client, ttl: 260}),
     saveUninitialized: false,
     resave: false,
     cookie: { maxAge: 900000000000000 }
   })
);

app.use('/', indexRouter);
app.use('/users', usersRouter);
app.use('/get_nmap', getNmapRouter);
app.use('/get_hostname', getHostname);
app.use('/get_whois', getWhois);
app.use('/get_mac_id', getMacID);
app.use('/get_mtu_size', getMTUSize);
app.use('/get_complete_data', getCompleteData);
app.use('/check_is_tor', checkIsTor);
app.use('/test_ping', testPing);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});


module.exports = app;