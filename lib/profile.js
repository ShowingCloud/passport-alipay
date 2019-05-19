/**
 * Parse profile.
 *
 * @param {Object|String} json
 * @return {Object}
 * @api private
 */
exports.parse = function (json) {
  if (typeof json === 'string') {
    json = JSON.parse(json);
  }

  const profile = {};
  profile.id = String(json.user_id);
  profile.displayName = json.nick_name;
  profile.avatar = json.avatar;
  profile.photos = [{ value: json.avatar }];
  return profile;
};
