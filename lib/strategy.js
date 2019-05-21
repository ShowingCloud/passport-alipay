const passport = require('passport-strategy');

const Alipay = require('./alipay');
const Profile = require('./profile');

module.exports = class AlipayStrategy extends passport.Strategy {
  constructor(options, verify) {
    const opt = options || {};

    if (!verify) {
      throw new TypeError('AlipayStrategy required a verify callback');
    }
    if (typeof verify !== 'function') {
      throw new TypeError('verify must be function');
    }
    if (!opt.appId || !opt.alipayPublicKey || !opt.privateKey) {
      throw new TypeError('AlipayStrategy requires app configurations');
    }

    super(opt, verify);

    this.name = opt.name || 'alipay';

    this.verify = verify;
    this.oauth = new Alipay(opt);
    this.appId = opt.appId;
    this.scope = opt.scope || 'auth_user';
    this.state = opt.state || 'ALIPAY';
    this.callbackURL = opt.callbackURL;
    this.passReqToCallback = opt.passReqToCallback;
  }

  authenticate(req, options) {
    if (!req._passport) {
      return this.error(new Error('passport.initialize() middleware not in use'));
    }

    const opt = options || {};

    if (req.query && req.query.state && !req.query.auth_code) {
      return this.fail(401);
    }

    if (req.query && req.query.auth_code) {
      const scope = opt.scope || this.scope || 'auth_user';
      const { auth_code } = req.query;

      return this.oauth.getAccessToken(auth_code, (err, params) => {
        function verified(error, user, info) {
          if (error) {
            return this.error(error);
          }
          if (!user) {
            return this.fail(info);
          }
          return this.success(user, info);
        }

        if (err) {
          return this.error(err);
        }

        if (!scope.indexOf('auth_base')) {
          const profile = {
            id: params.user_id,
          };

          try {
            if (this.passReqToCallback) {
              return this.verify(req, params.access_token, params.refresh_token, profile, verified);
            }
            return this.verify(params.access_token, params.refresh_token, profile, verified);
          } catch (ex) {
            return this.error(ex);
          }
        } else {
          return this.oauth.getUser(params.access_token, (error, rawProfile) => {
            if (error) {
              return this.error(error);
            }

            const profile = Profile.parse(rawProfile);
            profile.provider = 'alipay';
            profile._json = rawProfile;

            try {
              if (this.passReqToCallback) {
                return this.verify(req, params.access_token, params.refresh_token,
                  profile, verified);
              }
              return this.verify(params.access_token, params.refresh_token, profile, verified);
            } catch (ex) {
              return this.error(ex);
            }
          });
        }
      });
    }

    if (opt.failureRedirect) {
      return this.redirect(opt.failureRedirect, 302);
    }

    const appId = opt.appId || this.appId;
    const scope = opt.scope || this.scope || 'auth_user';
    const state = opt.state || this.state || 'ALIPAY';
    const callbackURL = opt.callbackURL || this.callbackURL;

    const url = `https://openauth.alipay.com/oauth2/publicAppAuthorize.htm?app_id=${appId}&scope=${scope}&state=${state}&redirect_uri=${encodeURIComponent(callbackURL)}`;
    return this.redirect(url, 302);
  }
};
