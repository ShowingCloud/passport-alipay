const fs = require('fs');
const crypto = require('crypto');
const moment = require('moment');

const iconv = require('iconv-lite');
const request = require('request');

const Promise = require('bluebird');
const NodeRSA = require('node-rsa');

const ALIPAY_GATEWAY = 'https://openapi.alipay.com/gateway.do';

function createPromiseCallback() {
  let cb;
  const promise = new Promise((resolve, reject) => {
    cb = (err, data) => {
      if (err) return reject(err);
      return resolve(data);
    };
  });
  cb.promise = promise;
  return cb;
}

const paramsFilter = (params) => {
  const result = {};
  if (!params) {
    return result;
  }
  Object.entries(params).forEach((key, param) => {
    if (param && param !== '' && key !== 'sign') {
      result[key] = param;
    }
  });
  return result;
};

const toQueryString = (params) => {
  let result = '';
  Object.keys(params).sort().forEach((sortKey) => {
    result += `${sortKey}=${params[sortKey]}&`;
  });

  if (result.length > 0) {
    return result.slice(0, -1);
  }
  return result;
};

module.exports = class Alipay {
  constructor(options) {
    this.options = options;
  }

  encryptedParams(params) {
    const qs = toQueryString(paramsFilter(params));
    const key = new NodeRSA(fs.readFileSync(this.options.alipayPublicKey), {
      encryptionScheme: 'pkcs8',
    });
    const encrypted = key.encrypt(qs, 'base64');
    return encrypted;
  }

  decryptedParams(toDecrypt) {
    const key = new NodeRSA(fs.readFileSync(this.options.privateKey), {
      encryptionScheme: 'pkcs8',
    });
    const decrypted = key.decrypt(toDecrypt, 'utf8');
    return decrypted;
  }

  generateSign(params) {
    const qs = toQueryString(paramsFilter(params));
    const signed = crypto.createSign('RSA-SHA256').update(Buffer.from(qs, 'utf8')).sign(fs.readFileSync(this.options.privateKey), 'base64');
    return signed;
  }

  verifySign(params, signature) {
    const qs = toQueryString(paramsFilter(params));
    const verified = crypto.createVerify('RSA-SHA256').update(Buffer.from(qs, 'utf8')).verify(fs.readFileSync(this.options.alipayPublicKey), signature, 'base64');
    return verified;
  }

  getAccessToken(code, cb) {
    const callback = cb || createPromiseCallback();

    const params = {
      app_id: this.options.appId,
      method: 'alipay.system.oauth.token',
      format: 'JSON',
      charset: 'gbk',
      sign_type: 'RSA2',
      timestamp: moment().format('YYYY-MM-DD HH:mm:ss'),
      version: '1.0',
      grant_type: 'authorization_code',
      code: code,
    };
    params.sign = this.generateSign(params);

    request({
      url: ALIPAY_GATEWAY,
      method: 'POST',
      form: params,
      encoding: null,
    }, (err, response, body) => {
      if (err) {
        callback(err);
      } else {
        const data = JSON.parse(iconv.decode(body, 'GBK'));

        if (data.error_response) {
          callback(new Error(data.error_response.msg));
        } else {
          callback(null, data.alipay_system_oauth_token_response || {});
        }
      }
    });

    return callback.promise;
  }

  getUser(token, cb) {
    const callback = cb || createPromiseCallback();

    const params = {
      app_id: this.options.appId,
      method: 'alipay.user.info.share',
      format: 'JSON',
      charset: 'gbk',
      sign_type: 'RSA2',
      timestamp: moment().format('YYYY-MM-DD HH:mm:ss'),
      version: '1.0',
      auth_token: token,
    };
    params.sign = this.generateSign(params);

    request({
      url: ALIPAY_GATEWAY,
      method: 'POST',
      form: params,
      encoding: null,
    }, (err, response, body) => {
      if (err) {
        callback(err);
      } else {
        const data = JSON.parse(iconv.decode(body, 'GBK'));

        if (data.error_response) {
          callback(new Error(data.error_response.msg));
        } else {
          callback(null, data.alipay_user_info_share_response || {});
        }
      }
    });

    return callback.promise;
  }
};
