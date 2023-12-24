module.exports.sanitizeUrl = function sanitizeUrl(url) {
  if (url.startsWith('http')) {
    return url;
  }

  return `https://${url}`;
};
