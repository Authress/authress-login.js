const cookieManager = require('cookie');
const jwtManager = require('jsonwebtoken');
const querystring = require('querystring');
const crypto = require('crypto');
const base64url = require('base64url');

const HttpClient = require('./src/httpClient');

let userSessionResolver;
let userSessionPromise = new Promise(resolve => userSessionResolver = resolve);

class LoginClient {
  /**
   * @constructor constructs the LoginClient with a given configuration
   * @param {Object} settings
   * @param {string} settings.authenticationServiceUrl Your Authress custom domain - see https://authress.io/app/#/manage?focus=applications
   * @param {string} settings.applicationId the Authress applicationId for this app - see https://authress.io/app/#/manage?focus=applications
   * @param {Object} [logger] a configured logger object, optionally `console`, which can used to display debug and warning messages.
   */
  constructor(settings, logger) {
    this.settings = Object.assign({}, settings);
    this.logger = logger || console;
    this.httpClient = new HttpClient(this.settings.authenticationServiceUrl);
  }

  /**
   * @description Gets the user's profile data and returns it if it exists. Should be called after {@link userSessionExists} or it will be empty.
   * @return {Object} The user data object.
   */
  getUserData() {
    const cookies = cookieManager.parse(document.cookie);
    const userData = cookies.user && jwtManager.decode(cookies.user);
    return userData && {
      userId: userData.sub,
      email: userData.email
    };
  }

  /**
   * @description Async wait for a user session to exist. Will block until {@link userSessionExists} or {@link authenticate} is called.
   * @return {Promise<void>}
   */
  async waitForUserSession() {
    try {
      await userSessionPromise;
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * @description Call this function on every route change. It will check if the user just logged in or is still logged in.
   * @return {Promise<Boolean>} Returns truthy if there a valid existing session, falsy otherwise.
   */
  async userSessionExists() {
    if (window.location.hostname === 'localhost') {
      const parameters = querystring.parse(window.location.search.slice(1));
      if (parameters.nonce && parameters.access_token) {
        const newUrl = new URL(window.location);
        newUrl.searchParams.delete('nonce');
        newUrl.searchParams.delete('access_token');
        newUrl.searchParams.delete('id_token');
        newUrl.searchParams.delete('state');
        history.pushState({}, undefined, newUrl.toString());
        const nonce = JSON.parse(localStorage.getItem('AuthenticationRequestNonce') || '{}').nonce;
        localStorage.removeItem('AuthenticationRequestNonce');
        if (nonce && nonce !== parameters.nonce) {
          const error = Error('Prevented a reply attack reusing the authentication request');
          error.code = 'InvalidNonce';
          throw error;
        }
        const idToken = jwtManager.decode(parameters.id_token);
        document.cookie = cookieManager.serialize('authorization', parameters.access_token, { expires: new Date(idToken.exp * 1000), path: '/' });
        document.cookie = cookieManager.serialize('user', parameters.id_token, { expires: new Date(idToken.exp * 1000), path: '/' });
        userSessionResolver();
        return true;
      }
      // Otherwise check cookies and then force the user to log in
    }

    const userData = this.getUserData();
    // User is already logged in
    if (userData) {
      this.logger.debug({ title: 'User is logged in' });
      userSessionResolver();
      return true;
    }

    if (window.location.hostname !== 'localhost') {
      await this.httpClient.get('/session', true);
      const newUserData = this.getUserData();
      // User session exists and now is logged in
      if (newUserData) {
        this.logger.debug({ title: 'User is logged in' });
        userSessionResolver();
        return true;
      }
    }
    return false;
  }

  /**
   * @description Logs a user in, if the user is not logged in, will redirect the user to their selected connection/provider and then redirect back to the {@link redirectUrl}.
   * @param {String} connectionId Specify which provider connection that user would like to use to log in - see https://authress.io/app/#/manage?focus=connections
   * @param {String} [redirectUrl=${window.location.href}] Specify where the provider should redirect to the user to in your application. If not specified with be the current location href. Must be a valid redirect url matching what is defined in the application in the Authress Management portal.
   * @param {Boolean} [force=false] Force getting new credentials.
   * @return {Promise<Boolean>} Is there a valid existing session.
   */
  async authenticate({ connectionId, redirectUrl, force }) {
    if (!force && await this.userSessionExists()) {
      if (redirectUrl && redirectUrl !== window.location.href) {
        window.location.assign(redirectUrl);
      }
      return true;
    }

    const codeVerifier = crypto.randomBytes(64).toString('hex');
    const hash = crypto.createHash('sha256').update(codeVerifier).digest();
    const codeChallenge = base64url(hash);

    const requestOptions = await this.httpClient.post('/authentication', false, {
      redirectUrl: redirectUrl || window.location.href, codeChallengeMethod: 'S256', codeChallenge,
      connectionId,
      applicationId: this.settings.applicationId
    });
    localStorage.setItem('AuthenticationRequestNonce', JSON.stringify({ nonce: requestOptions.data.authenticationRequestId, codeVerifier, lastConnectionId: connectionId }));
    window.location.assign(requestOptions.data.authenticationUrl);

    // Prevent the current UI from taking any action once we decided we need to log in.
    await new Promise(resolve => setTimeout(resolve, 5000));
    return false;
  }

  /**
   * @description Gets the user's bearer token to be used in the Authorization header as a Bearer token. This method blocks on a valid user session being created. So call after {@link userSessionExists}. Additionally, if the application configuration specifies that tokens should be secured from javascript, the token will be a hidden cookie only visible to service APIs and cannot be fetched from javascript.
   * @return {Promise<String>} The Authorization Bearer token.
   */
  async getToken() {
    await this.waitForUserSession();
    const cookies = cookieManager.parse(document.cookie);
    if (!cookies.authorization && cookies.user) {
      const error = Error('Token is configured to be restricted and is set to use cookie authentication. This setting can be changed for this application at https://authress.io.');
      error.code = 'RestrictedToken';
      throw error;
    }
    return cookies.authorization;
  }

  /**
   * @description Log the user out removing the current user's session
   */
  async logout() {
    document.cookie = cookieManager.serialize('authorization', '', { expires: new Date(), path: '/' });
    document.cookie = cookieManager.serialize('user', '', { expires: new Date(), path: '/' });
    // Reset user local session
    userSessionPromise = new Promise(resolve => userSessionResolver = resolve);
    await this.httpClient.delete('/session', true);
  }
}

module.exports = { LoginClient };

