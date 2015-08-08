# passport-mongodb

MongoDB (using mongoose) support for Passport. Turnkey magic!

## Installation

```bash
$ npm install passport-mongodb
```

## Usage

Simplest setup:

```javascript
var passport = require('passport'),
    passportMongo = require('passport-mongodb'),
    mongoose = require('mongoose'),
    app = require('koa')(),
    router = require('koa-router')();

// Connect via mongoose
mongoose.connect(...);

/* Some time passes—punch is served, life is generally merry. */

passportMongo.setup(passport);

/* Usual passport config and app stuff goes here. */

router.get('/test', passport.authenticate('mongodb'), function* () {
  return this.body = "Amazing, " + this.user.displayName + "!" ;
});
```

The `setup` method provides sane defaults for serialisation and
deserialisation of the `User` object, and adds the `Strategy` with defaults
to the `passport` instance.

`passportMongo` also has exported the `User` model and `Strategy` class for
your interactions and customisation as necessary.

## License

ISC
