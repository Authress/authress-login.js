const cookieManager = require('cookie');
const base64url = require('./base64url');

const HttpClient = require('./httpClient');
const jwtManager = require('./jwtManager');

let userSessionResolver;
let userSessionPromise = new Promise(resolve => userSessionResolver = resolve);

let userSessionSequencePromise = null;

const AuthenticationRequestNonceKey = 'AuthenticationRequestNonce';

class LoginClient {
  /**
   * @constructor constructs the LoginClient with a given configuration
   * @param {Object} settings
   * @param {string} settings.authressLoginHostUrl Your Authress custom domain - see https://authress.io/app/#/manage?focus=applications
   * @param {string} settings.applicationId the Authress applicationId for this app - see https://authress.io/app/#/manage?focus=applications
   * @param {Object} [logger] a configured logger object, optionally `console`, which can used to display debug and warning messages.
   */
  constructor(settings, logger) {
    this.settings = Object.assign({}, settings);
    this.logger = logger || console;
    const hostUrl = this.settings.authressLoginHostUrl || this.settings.authenticationServiceUrl || '';

    if (!hostUrl) {
      throw Error('Missing required property "authressLoginHostUrl" in LoginClient constructor. Custom Authress Domain Host is required.');
    }

    this.hostUrl = `https://${hostUrl.replace(/^(https?:\/+)/, '')}`;
    this.httpClient = new HttpClient(this.hostUrl);
    this.enableCredentials = true;
  }

  /**
   * @deprecated
   */
  getUserData() {
    return this.getUserIdentity();
  }

  /**
   * @description Gets the user's profile data and returns it if it exists. Should be called after {@link userSessionExists} or it will be empty.
   * @return {Object} The user data object.
   */
  getUserIdentity() {
    const cookies = cookieManager.parse(document.cookie);
    const userData = cookies.user && jwtManager.decode(cookies.user);
    if (!userData) {
      return null;
    }
    userData.userId = userData.sub;
    return userData;
  }

  /**
   * @description Gets the user's credentials that were generated as part of the connection provider. These credentials work directly with that provider.
   * @return {Promise<UserCredentials?>} The user's connection credentials.
   */
  async getConnectionCredentials() {
    await this.waitForUserSession();

    try {
      const token = await this.ensureToken();
      const credentialsResult = await this.httpClient.get('/session/credentials', this.enableCredentials, { Authorization: token && `Bearer ${token}` });
      return credentialsResult.data;
    } catch (error) {
      return null;
    }
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
  userSessionExists() {
    if (userSessionSequencePromise) {
      return userSessionSequencePromise = userSessionSequencePromise
      .catch(() => { /* ignore since we always want to continue even after a failure */ })
      .then(() => this.userSessionContinuation());
    }
    return userSessionSequencePromise = this.userSessionContinuation();
  }

  async userSessionContinuation() {
    const urlSearchParams = new URLSearchParams(window.location.search);
    const newUrl = new URL(window.location);

    let authRequest = {};
    try {
      authRequest = JSON.parse(localStorage.getItem(AuthenticationRequestNonceKey) || '{}');
      localStorage.removeItem(AuthenticationRequestNonceKey);
      this.enableCredentials = authRequest.enableCredentials !== false;
    } catch (error) {
      console.debug('LocalStorage failed in Browser', error);
    }

    if (authRequest.nonce && urlSearchParams.get('code')) {
      if (authRequest.nonce !== urlSearchParams.get('nonce')) {
        const error = Error('Prevented a reply attack reusing the authentication request');
        error.code = 'InvalidNonce';
        throw error;
      }

      newUrl.searchParams.delete('nonce');
      newUrl.searchParams.delete('iss');
      newUrl.searchParams.delete('code');
      history.replaceState({}, undefined, newUrl.toString());

      const code = urlSearchParams.get('code') === 'cookie' ? cookieManager.parse(document.cookie)['auth-code'] : urlSearchParams.get('code');
      const request = { grant_type: 'authorization_code', redirect_uri: authRequest.redirectUrl, client_id: this.settings.applicationId, code, code_verifier: authRequest.codeVerifier };
      const tokenResult = await this.httpClient.post(`/authentication/${authRequest.nonce}/tokens`, this.enableCredentials, request);
      const idToken = jwtManager.decode(tokenResult.data.id_token);
      const expiry = tokenResult.data.expires_in && new Date(Date.now() + tokenResult.data.expires_in * 1000) || new Date(idToken.exp * 1000);
      document.cookie = cookieManager.serialize('authorization', tokenResult.data.access_token || '', { expires: expiry, path: '/' });
      document.cookie = cookieManager.serialize('user', tokenResult.data.id_token || '', { expires: expiry, path: '/' });
      userSessionResolver();
      return true;
    }

    if (window.location.hostname === 'localhost') {
      if (urlSearchParams.get('nonce') && urlSearchParams.get('access_token')) {
        if (authRequest.nonce && authRequest.nonce !== urlSearchParams.get('nonce')) {
          const error = Error('Prevented a reply attack reusing the authentication request');
          error.code = 'InvalidNonce';
          throw error;
        }

        newUrl.searchParams.delete('nonce');
        newUrl.searchParams.delete('iss');
        newUrl.searchParams.delete('nonce');
        newUrl.searchParams.delete('expires_in');
        newUrl.searchParams.delete('access_token');
        newUrl.searchParams.delete('id_token');
        history.replaceState({}, undefined, newUrl.toString());

        const idToken = jwtManager.decode(urlSearchParams.get('id_token'));
        const expiry = Number(urlSearchParams.get('expires_in')) && new Date(Date.now() + Number(urlSearchParams.get('expires_in')) * 1000) || new Date(idToken.exp * 1000);
        document.cookie = cookieManager.serialize('authorization', urlSearchParams.get('access_token') || '', { expires: expiry, path: '/' });
        document.cookie = cookieManager.serialize('user', urlSearchParams.get('id_token') || '', { expires: expiry, path: '/' });
        userSessionResolver();
        return true;
      }
      // Otherwise check cookies and then force the user to log in
    }

    const userData = this.getUserIdentity();
    // User is already logged in
    if (userData) {
      userSessionResolver();
      return true;
    }

    if (window.location.hostname !== 'localhost') {
      try {
        const sessionResult = await this.httpClient.get('/session', this.enableCredentials);
        // In the case that the session contains non cookie based data, store it back to the cookie for this domain
        if (sessionResult.data.access_token) {
          const idToken = jwtManager.decode(sessionResult.data.id_token);
          const expiry = sessionResult.data.expires_in && new Date(Date.now() + sessionResult.data.expires_in * 1000) || new Date(idToken.exp * 1000);
          document.cookie = cookieManager.serialize('authorization', sessionResult.data.access_token || '', { expires: expiry, path: '/' });
          document.cookie = cookieManager.serialize('user', sessionResult.data.id_token || '', { expires: expiry, path: '/' });
        }
        // await this.httpClient.patch('/session', true, {});
      } catch (error) { /**/ }
      const newUserData = this.getUserIdentity();
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
   * @param {String} [connectionId] Specify which provider connection that user would like to use to log in - see https://authress.io/app/#/manage?focus=connections
   * @param {String} [tenantLookupIdentifier] Instead of connectionId, specify the tenant lookup identifier to log the user with the mapped tenant - see https://authress.io/app/#/manage?focus=tenants
   * @param {String} [responseLocation=cookie] Store the credentials response in the specified location. Options are either 'cookie' or 'query'.
   * @param {String} [flowType=token id_token] The type of credentials returned in the response. The list of options is any of 'code token id_token' separated by a space. Select token to receive an access_token, id_token to return the user identity in an JWT, and code for the authorization_code grant_type flow.
   * @param {String} [redirectUrl=${window.location.href}] Specify where the provider should redirect to the user to in your application. If not specified, the default is the current location href. Must be a valid redirect url matching what is defined in the application in the Authress Management portal.
   * @param {Object} [connectionProperties] Connection specific properties to pass to the identity provider. Can be used to override default scopes for example.
   * @param {Boolean} [force=false] Force getting new credentials.
   * @return {Promise<Boolean>} Is there a valid existing session.
   */
  async authenticate({ connectionId, tenantLookupIdentifier, redirectUrl, force, responseLocation, flowType, connectionProperties, openType }) {
    if (responseLocation && responseLocation !== 'cookie' && responseLocation !== 'query' && responseLocation !== 'none') {
      const e = Error('Authentication response location is not valid');
      e.code = 'InvalidResponseLocation';
      throw e;
    }

    if (!force && await this.userSessionExists()) {
      return true;
    }

    if (!connectionId && !tenantLookupIdentifier) {
      const e = Error('connectionId or tenantLookupIdentifier must be specified');
      e.code = 'InvalidConnection';
      throw e;
    }

    const sha256 = str => crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));

    const generateNonce = async () => {
      const hash = await sha256(crypto.getRandomValues(new Uint32Array(32)).toString());
      // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest
      const hashArray = Array.from(new Uint8Array(hash));
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    };

    const codeVerifier = await generateNonce();
    const hash = await sha256(codeVerifier);
    const codeChallenge = base64url.encode(hash);

    try {
      const normalizedRedirectUrl = redirectUrl && new URL(redirectUrl).toString();
      const selectedRedirectUrl = normalizedRedirectUrl || window.location.href;
      const requestOptions = await this.httpClient.post('/authentication', false, {
        redirectUrl: selectedRedirectUrl, codeChallengeMethod: 'S256', codeChallenge,
        connectionId, tenantLookupIdentifier,
        connectionProperties,
        applicationId: this.settings.applicationId,
        responseLocation, flowType
      });
      localStorage.setItem(AuthenticationRequestNonceKey, JSON.stringify({
        nonce: requestOptions.data.authenticationRequestId, codeVerifier, lastConnectionId: connectionId, tenantLookupIdentifier, redirectUrl: selectedRedirectUrl,
        enableCredentials: requestOptions.data.enableCredentials
      }));
      if (openType === 'tab') {
        window.open(requestOptions.data.authenticationUrl, '_blank');
      } else {
        window.location.assign(requestOptions.data.authenticationUrl);
      }
    } catch (error) {
      if (error.status >= 400 && error.status < 500) {
        const e = Error(error.data.title || error.data.errorCode);
        e.code = error.data.errorCode;
        throw e;
      }
      throw error;
    }

    // Prevent the current UI from taking any action once we decided we need to log in.
    await new Promise(resolve => setTimeout(resolve, 5000));
    return false;
  }

  /**
   * @description Ensures the user's bearer token exists. To be used in the Authorization header as a Bearer token. This method blocks on a valid user session being created, and expects {@link authenticate} to have been called first. Additionally, if the application configuration specifies that tokens should be secured from javascript, the token will be a hidden cookie only visible to service APIs and will not be returned. If the token is expired and the session is still valid, then it will automatically generate a new token directly from Authress.
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
   * @description Log the user out removing the current user's session. If the user is not logged in this has no effect. If the user is logged in via secure session, the the redirect url will be ignored. If the user is logged in without a secure session the user agent will be redirected to the hosted login and then redirected to the {@link redirectUrl}.
   * @param {string} [redirectUrl='window.location.href'] Optional redirect location to return the user to after logout. Will only be used for cross domain sessions.
   */
  async logout(redirectUrl) {
    document.cookie = cookieManager.serialize('authorization', '', { expires: new Date(), path: '/' });
    document.cookie = cookieManager.serialize('user', '', { expires: new Date(), path: '/' });

    // Localhost also has enableCredentials set, so this path is only for cross domain logins
    if (!this.enableCredentials) {
      const fullLogoutUrl = new URL('/logout', this.hostUrl);
      const referrer = (document.referrer || document.referer) ? new URL(document.referrer || document.referer).toString() : undefined;
      fullLogoutUrl.searchParams.set('redirect_uri', redirectUrl || referrer);
      fullLogoutUrl.searchParams.set('client_id', this.settings.applicationId);
      window.location.assign(fullLogoutUrl.toString());
      return;
    }

    // Reset user local session
    userSessionPromise = new Promise(resolve => userSessionResolver = resolve);
    try {
      await this.httpClient.delete('/session', this.enableCredentials);
    } catch (error) { /**/ }
  }
}

module.exports = { LoginClient };
