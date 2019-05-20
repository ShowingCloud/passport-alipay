const util = require('util');
const passport = require('passport-strategy');

const Alipay = require('./alipay');
const Profile = require('./profile');

function AlipayStrategy(options, verify) {
  const opt = options || {};

  if (!verify) {
    throw new TypeError('AlipayStrategy required a verify callback');
  }

  if (typeof verify !== 'function') {
    throw new TypeError('verify must be function');
  }

  if (!opt.appId || !opt.alipayPublicKey || !opt.privateKey) {
    throw new TypeError('AlipayStrategy requires a app configurations');
  }

  passport.Strategy.call(this, opt, verify);

  this.name = opt.name || 'Alipay';

  this.verify = verify;
  this.oauth = new Alipay(opt);
  this.appId = opt.appId;
  this.scope = opt.scope || 'auth_user';
  this.state = opt.state || 'ALIPAY';
  this.callbackURL = opt.callbackURL;
  this.passReqToCallback = opt.passReqToCallback;
}

/**
 * Inherit from 'passort.Strategy'
 */
util.inherits(AlipayStrategy, passport.Strategy);

AlipayStrategy.prototype.authenticate = (req, options) => {
  const self = this;

  if (!req.passport) {
    return self.error(new Error('passport.initialize() middleware not in use'));
  }

  const opt = options || {};

  if (req.query && req.query.state && !req.query.auth_code) {
    return self.fail(401);
  }

  if (req.query && req.query.auth_code) {
    const scope = opt.scope || self.scope || 'auth_user';
    const { authCode } = req.query;

    return self.oauth.getAccessToken(authCode, (err, params) => {
      function verified(error, user, info) {
        if (error) {
          return self.error(error);
        }
        if (!user) {
          return self.fail(info);
        }
        return self.success(user, info);
      }

      if (err) {
        return self.error(err);
      }

      if (!scope.indexOf('auth_base')) {
        const profile = {
          id: params.user_id,
        };

        try {
          if (self.passReqToCallback) {
            return self.verify(req, params.access_token, params.refresh_token, profile, verified);
          }
          return self.verify(params.access_token, params.refresh_token, profile, verified);
        } catch (ex) {
          return self.error(ex);
        }
      } else {
        return self.oauth.getUser(params.access_token, (error, rawProfile) => {
          if (error) {
            return self.error(error);
          }

          const profile = Profile.parse(rawProfile);
          profile.provider = 'alipay';
          profile.json = rawProfile;

          try {
            if (self.passReqToCallback) {
              return self.verify(req, params.access_token, params.refresh_token, profile, verified);
            }
            return self.verify(params.access_token, params.refresh_token, profile, verified);
          } catch (ex) {
            return self.error(ex);
          }
        });
      }
    });
  } if (opt.failureRedirect) {
    return self.redirect(opt.failureRedirect, 302);
  }
  const appId = opt.appId || self.appId;
  const scope = opt.scope || self.scope || 'auth_user';
  const state = opt.state || self.state || 'ALIPAY';
  const callbackURL = opt.callbackURL || self.callbackURL;

  const url = `https://openauth.alipay.com/oauth2/publicAppAuthorize.htm?app_id=${appId}&scope=${scope}&state=${state}&redirect_uri=${encodeURIComponent(callbackURL)}`;
  return self.redirect(url, 302);
};

module.exports = AlipayStrategy;
