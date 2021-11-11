const mongoose = require('mongoose');
const { RateLimiterMongo } = require('rate-limiter-flexible');

const mongoOpts = {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  };
const mongoConn = mongoose.createConnection(`mongodb://localhost:27017/ratelim?retryWrites=true&writeConcern=majority`, mongoOpts);

///////////////////////
// DDoS Rate Limiter //
///////////////////////
const opts = {
  storeClient: mongoConn,
  points: 9, // Number of points
  duration: 1, // Per second(s)
  blockDuration: 10,
};
const rateLimiterMongo = new RateLimiterMongo(opts);

module.exports.rateLimiterMiddleware = (req, res, next) => {
  rateLimiterMongo.consume(req.ip)
    .then(() => {
      next();
    })
    .catch(() => {
      res.status(429).send('Too many requests');
    });
};

/////////////////////////
// Login Rate Limiters //
/////////////////////////
const maxWrongAttemptsByIPperDay = 70;
const maxWrongAttemptsByIPperMinute = 6;
const maxConsecutiveFailsByUsernameAndIP = 10;

module.exports.limiterSlowBruteByIP = new RateLimiterMongo({
    storeClient: mongoConn,
    keyPrefix: 'login_fail_ip_per_day',
    points: maxWrongAttemptsByIPperDay,
    duration: 60 * 60 * 24,
    blockDuration: 60 * 60 * 24, // Block for 1 day, if 70 wrong attempts per IP per day
});

module.exports.limiterFastBruteByIP = new RateLimiterMongo({
    storeClient: mongoConn,
    keyPrefix: 'login_fail_ip_per_minute',
    points: maxWrongAttemptsByIPperMinute,
    duration: 30,
    blockDuration: 60 * 5, // Block for 5 minutes, if 6 wrong attempts per 30 seconds
});

module.exports.limiterConsecutiveFailsByUsernameAndIP  = new RateLimiterMongo({
    storeClient: mongoConn,
    keyPrefix: 'login_fail_consecutive_username_and_ip',
    points: maxConsecutiveFailsByUsernameAndIP,
    duration: 60 * 60 * 24 * 15, // Store number for 15 days since first fail
    blockDuration: 60 * 60, // Block for 1 hour
});

module.exports.maxWrongAttemptsByIPperDay = maxWrongAttemptsByIPperDay;
module.exports.maxWrongAttemptsByIPperMinute = maxWrongAttemptsByIPperMinute;
module.exports.maxConsecutiveFailsByUsernameAndIP = maxConsecutiveFailsByUsernameAndIP;


const maxResendsByUsername = 2;

module.exports.limiterResends  = new RateLimiterMongo({
  storeClient: mongoConn,
  keyPrefix: 'email_resends_by_username',
  points: maxResendsByUsername,
  duration: 60 * 60 * 4, // Store number for 4 hours since first
  blockDuration: 60 * 60, // Block for 1 hour
});

module.exports.maxResendsByUsername = maxResendsByUsername;
