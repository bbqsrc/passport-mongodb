'use strict';

var passport = require('passport-strategy'),
    crypto = require('mz/crypto'),
    mongoose = require('mongoose'),
    co = require('co'),
    constantTimeEquals = require('buffer-equal-constant-time'),
    Schema = mongoose.Schema;

var userSchema = new Schema({
  username: {
    type: String,
    index: true,
    unique: true,
    validate: function(v) {
      return v === v.toLowerCase();
    }
  },
  displayName: String,
  iterations: Number,
  salt: Schema.Types.Buffer,
  hash: Schema.Types.Buffer,
  flags: Array,
  data: { type: Schema.Types.Mixed, default: {} }
});

var defaults = {
  iterations: 4096,
  saltSize: 128,
  keyLength: 2048
};

userSchema.statics.createUser = function(username, password, options) {
  options = options || {};

  return co(function*() {
    username = username.trim();
    if (username === '') {
      throw new Error('invalid username');
    }

    if (password == null || password === '') {
      throw new Error('invalid password');
    }

    let flags = options.flags || [];

    let user = new (this.model('User'))({
      username: username.toLowerCase(),
      displayName: username,
      flags: flags,
      data: options.data
    });

    yield user.updatePassword(password, options);
    yield user.save();
    return user;
  }.bind(this));
};

userSchema.statics.authenticate = function(username, password) {
  return co(function*() {
    let user = yield this.findOne({username: username}).exec();

    if (!user) {
      return false;
    }

    let valid = yield user.verifyPassword(password);
    return valid ? user : false;
  }.bind(this));
};

userSchema.methods.verifyPassword = function(password) {
  return co(function*() {
    let key = yield crypto.pbkdf2(password, this.salt, this.iterations, this.hash.length, 'sha256');
    return constantTimeEquals(this.hash, key);
  }.bind(this));
};

userSchema.methods.updatePassword = function(password, options) {
  options = options || {};

  return co(function*() {
    if (password == null || password === '') {
      throw new Error('invalid password');
    }

    let iterations = options.iterations || defaults.iterations;
    let saltSize = options.saltSize || defaults.saltSize;
    let keyLength = options.keyLength || defaults.keyLength;

    let saltBuffer = yield crypto.randomBytes(saltSize);
    let key = yield crypto.pbkdf2(password, saltBuffer, iterations, keyLength, 'sha256');

    this.iterations = iterations;
    this.salt = saltBuffer;
    this.hash = key;

    return this;
  }.bind(this));
};

userSchema.methods.isAdmin = function() {
  return this.flags.indexOf('admin') > -1;
};

userSchema.methods.is = function(flag) {
  return this.flags.indexOf(flag) > -1;
};

userSchema.methods.isIn = function isIn(flags) {
  if (arguments.length > 1) {
    return isIn.call(this, arguments);
  }

  for (let flag of flags) {
    if (this.flags.indexOf(flag) > -1) {
      return true;
    }
  }

  return false;
};

var User = exports.User = mongoose.model('User', userSchema);

class Strategy /* extends passport.Strategy */ {
  constructor(options) {
    options = options || {};

    this._usernameField = options.usernameField || 'username';
    this._passwordField = options.passwordField || 'password';

    passport.Strategy.call(this); // super equivalent.
    this.name = 'mongodb';
  }

  authenticate(req, options) {
    options = options || {};

    if (!req.body) {
      return this.error(new TypeError(
        'No req.body; did you forget POST body parsing middleware?'));
    }

    let body = req.body;

    // Support `koa-better-body`-style parsing
    if (!body.username && !body.password && body.fields) {
      body = body.fields;
    }

    var username = body[this._usernameField];
    var password = body[this._passwordField];

    if (!username || !password) {
      return this.fail({ message: options.badRequestMessage || 'Missing credentials' }, 400);
    }

    return co(function*() {
      try {
        let user = yield User.authenticate(username, password);

        if (!user) {
          return this.fail();
        }

        return this.success(user);
      } catch (err) {
        return this.error(err);
      }
    }.bind(this));
  }
}
Strategy.prototype.constructor = new passport.Strategy;

exports.Strategy = Strategy;

function setup(p) {
  p.serializeUser(function(user, done) {
    done(null, user.id);
  });

  p.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      if (err) { return done(err, null); }

      done(null, user);
    });
  });

  p.use(new Strategy());
}

exports.setup = setup;
