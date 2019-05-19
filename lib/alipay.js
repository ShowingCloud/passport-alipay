

const _ = require('lodash');
const path = require('path');
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
  const promise = new Promise(((resolve, reject) => {
    cb = function (err, data) {
      if (err) return reject(err);
      return resolve(data);
    };
  }));
  cb.promise = promise;
  return cb;
}

// 除去数组中的空值和签名参数
const paramsFilter = function (params) {
  const result = {};
  if (!params) {
    return result;
  }
  for (const k in params) {
    if (!params[k] || params[k] === '' || k === 'sign') {
      continue;
    }
    result[k] = params[k];
  }
  return result;
};

// 将所有参数按照“参数=参数值”的模式用“&”字符拼接成字符串
const toQueryString = function (params) {
  let result = '';
  const sortKeys = Object.keys(params).sort();
  for (const i in sortKeys) {
    result += `${sortKeys[i]}=${params[sortKeys[i]]}&`;
  }
  if (result.length > 0) {
    return result.slice(0, -1);
  }
  return result;
};

const Alipay = function (options) {
  this._options = options;
  return this;
};

Alipay.prototype._encryptedParams = function (params) {
  const qs = toQueryString(paramsFilter(params));
  const key = new NodeRSA(fs.readFileSync(this._options.alipay_public_key), {
    encryptionScheme: 'pkcs8',
  });
  const encrypted = key.encrypt(qs, 'base64');
  return encrypted;
};

Alipay.prototype._decryptedParams = function (toDecrypt) {
  const key = new NodeRSA(fs.readFileSync(this._options.private_key), {
    encryptionScheme: 'pkcs8',
  });
  const decrypted = key.decrypt(toDecrypt, 'utf8');
  return decrypted;
};

Alipay.prototype._generateSign = function (params) {
  const qs = toQueryString(paramsFilter(params));
  const signed = crypto.createSign('RSA-SHA256').update(new Buffer(qs, 'utf8')).sign(fs.readFileSync(this._options.private_key), 'base64');
  return signed;
};

Alipay.prototype._verifySign = function (params, signature) {
  const qs = toQueryString(paramsFilter(params));
  const verified = crypto.createVerify('RSA-SHA256').update(new Buffer(qs, 'utf8')).verify(fs.readFileSync(this._options.alipay_public_key), signature, 'base64');
  return verified;
};

Alipay.prototype.getAccessToken = function (code, cb) {
  cb = cb || createPromiseCallback();

  const self = this;

  const params = {
    app_id: self._options.app_id,
    method: 'alipay.system.oauth.token',
    format: 'JSON',
    charset: 'gbk',
    sign_type: 'RSA2',
    timestamp: moment().format('YYYY-MM-DD HH:mm:ss'),
    version: '1.0',
    grant_type: 'authorization_code',
    code,
  };
  params.sign = self._generateSign(params);

  request({
    url: ALIPAY_GATEWAY,
    method: 'POST',
    form: params,
    encoding: null,
  }, (err, response, body) => {
    if (err) {
      cb(err);
    } else {
      const data = JSON.parse(iconv.decode(body, 'GBK'));

      if (data.error_response) {
        cb(new Error(data.error_response.msg));
      } else {
        cb(null, data.alipay_system_oauth_token_response || {});
      }
    }
  });

  return cb.promise;
};

Alipay.prototype.getUser = function (token, cb) {
  cb = cb || createPromiseCallback();

  const self = this;

  const params = {
    app_id: self._options.app_id,
    method: 'alipay.user.info.share',
    format: 'JSON',
    charset: 'gbk',
    sign_type: 'RSA2',
    timestamp: moment().format('YYYY-MM-DD HH:mm:ss'),
    version: '1.0',
    auth_token: token,
  };
  params.sign = self._generateSign(params);

  request({
    url: ALIPAY_GATEWAY,
    method: 'POST',
    form: params,
    encoding: null,
  }, (err, response, body) => {
    if (err) {
      cb(err);
    } else {
      const data = JSON.parse(iconv.decode(body, 'GBK'));

      if (data.error_response) {
        cb(new Error(data.error_response.msg));
      } else {
        cb(null, data.alipay_user_info_share_response || {});
      }
    }
  });

  return cb.promise;
};

module.exports = Alipay;
