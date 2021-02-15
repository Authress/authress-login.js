const cookieManager = require('cookie');
const jwtManager = require('jsonwebtoken');
const querystring = require('querystring');
const crypto = require('crypto');
const base64url = require('base64url');

const HttpClient = require('./src/httpClient');

let userSessionResolver;
let userSessionPromise = new Promise(resolve => userSessionResolver = resolve);

let userSessionSequencePromise = null;

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
    if (userSessionSequencePromise) {
      await userSessionSequencePromise.catch(() => { /* ignore since we always want to continue even after a failure */ });
    }
    return userSessionSequencePromise = this.userSessionContinuation();
  }

  async userSessionContinuation() {
    const parameters = querystring.parse(window.location.search.slice(1));
    const newUrl = new URL(window.location);
    newUrl.searchParams.delete('nonce');
    newUrl.searchParams.delete('access_token');
    newUrl.searchParams.delete('id_token');
    newUrl.searchParams.delete('state');
    newUrl.searchParams.delete('code');
    newUrl.searchParams.delete('iss');
    history.pushState({}, undefined, newUrl.toString());

    if (window.location.hostname === 'localhost') {
      if (parameters.nonce && parameters.access_token) {
        const authRequest = JSON.parse(localStorage.getItem('AuthenticationRequestNonce') || '{}');
        // Use in authorization code exchange with non-localhost
        // authRequest.codeVerifier
        localStorage.removeItem('AuthenticationRequestNonce');
        if (authRequest.nonce && authRequest.nonce !== parameters.nonce) {
          const error = Error('Prevented a reply attack reusing the authentication request');
          error.code = 'InvalidNonce';
          throw error;
        }
        const idToken = jwtManager.decode(parameters.id_token);
        document.cookie = cookieManager.serialize('authorization', parameters.access_token || '', { expires: new Date(idToken.exp * 1000), path: '/' });
        document.cookie = cookieManager.serialize('user', parameters.id_token || '', { expires: new Date(idToken.exp * 1000), path: '/' });
        userSessionResolver();
        return true;
      }
      // Otherwise check cookies and then force the user to log in
    }

    const userData = this.getUserData();
    // User is already logged in
    if (userData) {
      userSessionResolver();
      return true;
    }

    if (window.location.hostname !== 'localhost') {
      try {
        await this.httpClient.get('/session', true);
      } catch (error) { /**/ }
      const newUserData = this.getUserData();
      // User session exists and now is logged in
      if (newUserData) {
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
   * @description Ensures the user's bearer token exists. To be used in the Authorization header as a Bearer token. This method blocks on a valid user session being created, and expects {@link authenticate} to have been called first. Additionally, if the application configuration specifies that tokens should be secured from javascript, the token will be a hidden cookie only visible to service APIs and will not be returned.
   * @param {Object} [options] Options for getting a token including timeout configuration.
   * @param {Boolean} [options.timeoutInMillis=5000] Timeout waiting for user token to populate. After this time an error will be thrown.
   * @return {Promise<String>} The Authorization Bearer token if allowed otherwise null.
   */
  async ensureToken(options) {
    await this.userSessionExists();
    const inputOptions = Object.assign({ timeoutInMillis: 5000 }, options || {});
    const sessionWaiterAsync = this.waitForUserSession();
    const timeoutAsync = new Promise((resolve, reject) => setTimeout(reject, inputOptions.timeoutInMillis || 0));
    try {
      await Promise.race([sessionWaiterAsync, timeoutAsync]);
    } catch (timeout) {
      const error = Error('No token retrieved after timeout');
      error.code = 'TokenTimeout';
      throw error;
    }
    const cookies = cookieManager.parse(document.cookie);
    return cookies.authorization !== 'undefined' && cookies.authorization;
  }

  getToken() {
    return this.ensureToken();
  }

  /**
   * @description Log the user out removing the current user's session
   */
  async logout() {
    document.cookie = cookieManager.serialize('authorization', '', { expires: new Date(), path: '/' });
    document.cookie = cookieManager.serialize('user', '', { expires: new Date(), path: '/' });
    // Reset user local session
    userSessionPromise = new Promise(resolve => userSessionResolver = resolve);
    try {
      await this.httpClient.delete('/session', true);
    } catch (error) { /**/ }
  }
}

module.exports = { LoginClient };

