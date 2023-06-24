const base64url = require('./base64url');

class JwtManager {
  decode(token) {
    try {
      return token && JSON.parse(base64url.decode(token.split('.')[1]));
    } catch (error) {
      return null;
    }
  }

  decodeOrParse(token) {
    if (!token) {
      return null;
    }

    if (typeof token === 'object') {
      return token;
    }

    try {
      return JSON.parse(token);
    } catch (error) {
      return this.decode(token);
    }
  }

  decodeFull(token) {
    try {
      return token && {
        header: JSON.parse(base64url.decode(token.split('.')[0])),
        payload: JSON.parse(base64url.decode(token.split('.')[1]))
      };
    } catch (error) {
      return null;
    }
  }

  async getAuthCodes() {
    const codeVerifier = base64url.encode((window.crypto || window.msCrypto).getRandomValues(new Uint32Array(16)).toString());
    // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest
    const hashBuffer = await (window.crypto || window.msCrypto).subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier));
    const codeChallenge = base64url.encode(hashBuffer);
    return { codeVerifier, codeChallenge };
  }
}

module.exports = new JwtManager();
