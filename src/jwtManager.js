const base64url = require('./base64url');

class JwtManager {
  decode(token) {
    if (!token) {
      return null;
    }

    try {
      const parsedToken = JSON.parse(base64url.decode(token.split('.')[1]));
      // If the identity expires in less than 10 seconds from now, assume it is already expired.
      // * This blocks issues with intermittent access, and subsequent issues when the token has a limited finite lifetime
      // * All the Authress token server returns 5 second long JWT lifetimes to prevent issues with browsers refusing 0 second long lifetimes, so a buffer is required
      if (parsedToken.exp) {
        parsedToken.exp = parsedToken.exp - 10;
      }
      return parsedToken;
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
    if (!token) {
      return null;
    }

    try {
      const header = JSON.parse(base64url.decode(token.split('.')[0]));
      const payload = JSON.parse(base64url.decode(token.split('.')[1]));
      // If the identity expires in less than 10 seconds from now, assume it is already expired.
      // * This blocks issues with intermittent access, and subsequent issues when the token has a limited finite lifetime
      // * All the Authress token server returns 5 second long JWT lifetimes to prevent issues with browsers refusing 0 second long lifetimes, so a buffer is required
      if (payload.exp) {
        payload.exp = payload.exp - 10;
      }
      return { header, payload };
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
