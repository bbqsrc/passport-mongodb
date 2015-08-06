'use strict';

var app = require('koa')(),
    co = require('co'),
    passport = require('koa-passport'),
    mongoose = require('mongoose'),
    logger = require('koa-huggare'),
    session = require('koa-session'),
    bodyParser = require('koa-bodyparser'),
    router = require('koa-router')(),
    passportMongo = require('./index.js');

mongoose.connect('mongodb://localhost:27017/authtest');
var db = mongoose.connection;

app.keys = ['test key'];

passportMongo.setup(passport);

app.use(logger())
  .use(session({key: 'test.id'}, app))
  .use(passport.initialize())
  .use(passport.session());

app.use(function *(next) {
  try {
    yield next;
  } catch (err) {
    this.status = err.status || 500;
    this.body = 'Internal server error. Please contact an administrator.';
    this.app.emit('error', err, this);
  }
});

app.use(bodyParser());

router
.get('/', function*() {
  return this.body = this.req.user || 'no user!';
})
.get('/login', function* () {
  return this.body = '<form method=post><input name=username><input name=password><input type=submit></form>';
})
.post('/login', bodyParser(), passport.authenticate('mongodb'));

app.use(router.routes());

db.once('open', function() {
  co(function*() {
    if (!(yield passportMongo.User.findOne({username: 'test'}).exec())) {
      yield passportMongo.User.createUser('test', 'test');
    }

    app.listen(3010);
    console.log('listening on port 3010');
  });
});
