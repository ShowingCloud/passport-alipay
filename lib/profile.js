/**
 * Parse profile.
 *
 * @param {Object|String} json
 * @return {Object}
 * @api private
 */
exports.parse = (ret) => {
  let json = ret;
  if (typeof ret === 'string') {
    json = JSON.parse(ret);
  }

  const profile = {};
  profile.id = String(json.user_id);
  profile.displayName = json.nick_name;
  profile.avatar = json.avatar;
  profile.photos = [{ value: json.avatar }];
  return profile;
};
