function percentToByte(p) {
  return String.fromCharCode(parseInt(p.slice(1), 16));
}

function encodeBase64(str) {
  return btoa(encodeURIComponent(str).replace(/%[0-9A-F]{2}/g, percentToByte));
}

function byteToPercent(b) {
  return `%${`00${b.charCodeAt(0).toString(16)}`.slice(-2)}`;
}

function decodeBase64(str) {
  return decodeURIComponent(Array.from(atob(str), byteToPercent).join(''));
}

module.exports.decode = function decode(str) {
  return decodeBase64(str.replace(/-/g, '+').replace(/_/g, '/'));
};

module.exports.encode = function encode(str) {
  return encodeBase64(str)
  .replace(/\//g, '_')
  .replace(/\+/g, '-')
  .replace(/=+$/, '');
};
