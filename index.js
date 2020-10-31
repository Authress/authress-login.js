const cookieManager = require('cookie');
const jwtManager = require('jsonwebtoken');
const querystring = require('querystring');

const HttpClient = require('./src/httpClient');

class LoginClient {
  constructor(settings, logger) {
    this.settings = settings || {};
    this.logger = logger || console;
  }

  async ensureUserIsAuthenticated({ authenticationServiceUrl, applicationId, connectionId, redirectUrl }) {
    const httpClient = new HttpClient(authenticationServiceUrl);
    if (window.location.hostname === 'localhost') {
      const parameters = querystring.parse(window.location.search.slice(1));
      if (parameters.nonce && parameters.access_token) {
        const newUrl = new URL(window.location);
        newUrl.searchParams.delete('nonce');
        newUrl.searchParams.delete('access_token');
        newUrl.searchParams.delete('id_token');
        history.pushState({}, undefined, newUrl.toString());
        const nonce = localStorage.getItem('AuthenticationRequestNonce');
        localStorage.removeItem('AuthenticationRequestNonce');
        if (nonce && nonce !== parameters.nonce) {
          const error = Error('Prevented a reply attack reusing the authentication request');
          error.code = 'InvalidNonce';
          throw error;
        }
        const idToken = jwtManager.decode(parameters.id_token);
        document.cookie = cookieManager.serialize('authorization', parameters.access_token, { expires: new Date(idToken.exp * 1000), path: '/' });
        document.cookie = cookieManager.serialize('user', parameters.id_token, { expires: new Date(idToken.exp * 1000), path: '/' });
        return;
      }
      // Otherwise check cookies and then force the user to log in
    }

    const cookies = cookieManager.parse(document.cookie);
    // User is already logged in
    if (cookies.user) {
      this.logger.debug({ title: 'User is logged in' }, true);
      return;
    }

    if (window.location.hostname !== 'localhost') {
      await httpClient.getWithCredentials('/session');
      const newCookies = cookieManager.parse(document.cookie);

      if (newCookies.user) {
        this.logger.debug({ title: 'User is logged in' }, true);
        return;
      }
    }

    // const { v4: uuidv4 } = require('uuid');
    // const crypto = require('crypto');
    // const base64url = require('base64url');
    // // TODO: Convert to secure random;
    // // Store this
    // const pkceCode = uuidv4();
    // const hash = crypto.createHash('sha256').update(pkceCode).digest();
    // const pkceChallenge = base64url(hash);

    const requestOptions = await httpClient.post('/authentication', { redirectUrl: redirectUrl || window.location.href, connectionId, applicationId });
    localStorage.setItem('AuthenticationRequestNonce', requestOptions.data.authenticationRequestId);
    window.location.assign(requestOptions.data.authenticationUrl);
  }

  getToken() {
    const cookies = cookieManager.parse(document.cookie);
    if (!cookies.authorization && cookies.user) {
      const error = Error('Token is configured to be restricted and is set to use cookie authentication. This setting can be changed for this application at https://authress.io.');
      error.code = 'RestrictedToken';
      throw error;
    }
    return cookies.authorization;
  }

  getUserData() {
    const cookies = cookieManager.parse(document.cookie);
    const userData = cookies.user && jwtManager.decode(cookies.user);
    return userData && {
      userId: userData.sub,
      email: userData.email
    };
  }
}

module.exports = { LoginClient };

