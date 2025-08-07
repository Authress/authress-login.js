const cookieManager = require('cookie');
const take = require('lodash.take');

const windowManager = require('./windowManager');
const HttpClient = require('./httpClient');
const jwtManager = require('./jwtManager');
const { sanitizeUrl } = require('./util');
const userIdentityTokenStorageManager = require('./userIdentityTokenStorageManager');

let userSessionResolver;
let userSessionPromise = new Promise(resolve => userSessionResolver = resolve);

let userSessionSequencePromise = Promise.resolve();
let userSessionCheckIsInProgress = false;

const AuthenticationRequestNonceKey = 'AuthenticationRequestNonce';

class LoginClient {
  /**
   * @constructor constructs the LoginClient with a given configuration
   * @param {Object} settings
   * @param {String} settings.authressApiUrl Your Authress custom domain - see https://authress.io/app/#/manage?focus=applications
   * @param {String} settings.applicationId the Authress applicationId for this app - see https://authress.io/app/#/manage?focus=applications
   * @param {Object} [logger] a configured logger object, optionally `console`, which can used to display debug and warning messages.
   */
  constructor(settings, logger) {
    const settingsWithDefault = Object.assign({ applicationId: 'app_default' }, settings);
    this.logger = logger || console;
    const hostUrl = settingsWithDefault.authressApiUrl || settingsWithDefault.authressLoginHostUrl || settingsWithDefault.authenticationServiceUrl || '';

    if (!hostUrl) {
      throw Error('Missing required property "authressApiUrl" in LoginClient constructor. Custom Authress Domain Host is required.');
    }

    this.applicationId = settingsWithDefault.applicationId;
    if (!this.applicationId || this.applicationId.match(/^(sc_|ext_)/)) {
      const error = Error("You have incorrectly specified an Authress Service Client or Extension as the applicationId instead of a valid application. The applicationId is your application that your users will log into, usually hosted on your domain https://example.yourdomain.com. Users cannot log *into* a Service Client, but they can log in *with* one. Users can use a Service Client to log in, by setting the connection ID in the *authenticate({ connectionId })* method to be the Authress Service Client.\n(1) If you are building an Custom Login Portal, then the application ID should correspond to this login portal.\n(2) If you are replacing or extending an Authress connection, then specify the Service Client as the connectionId and the end user application as the applicationId.\n(3) If you are building a platform or plugin marketplace, where users will log into third party extensions or apps, then distribute in your SDK a wrapper for the Authress Extension Client using: import { extensionClient } from '@authress/login' found within this SDK.\n(4) If you aren't sure what to do here to fix the problem, the fastest and usually correct solution is go to https://authress.io/app/#/settings?focus=applications create a new application, specify your site in the application url property and then update the value here.");
      error.code = 'InvalidApplication';
      throw error;
    }

    this.hostUrl = sanitizeUrl(hostUrl);
    this.httpClient = new HttpClient(this.hostUrl, logger);
    this.lastSessionCheck = 0;

    this.enableCredentials = this.getMatchingDomainInfo(this.hostUrl);

    userIdentityTokenStorageManager.retainUserCookie = settings.retainUserCookie;

    if (!settingsWithDefault.skipBackgroundCredentialsCheck) {
      windowManager.onLoad(async () => {
        await this.userSessionExists(true);
      });
    }
  }

  getMatchingDomainInfo(hostUrlString) {
    const hostUrl = new URL(hostUrlString);

    if (windowManager.isLocalHost()) {
      return false;
    }

    const currentLocation = windowManager.getCurrentLocation();
    if (currentLocation.protocol !== 'https:') {
      return false;
    }

    const tokenUrlList = hostUrl.host.toLowerCase().split('.').reverse();
    // Login url may not be known all the time, in which case we will compare the token url to the appUrl
    const appUrlList = currentLocation.host.toLowerCase().split('.').reverse();

    let reversedMatchSegments = [];
    for (let segment of tokenUrlList) {
      const urlToTest = take(appUrlList, reversedMatchSegments.length + 1).join('.');
      const urlToMatch = reversedMatchSegments.concat(segment).join('.');
      if (urlToMatch !== urlToTest) {
        break;
      }

      reversedMatchSegments.push(segment);
    }

    if (reversedMatchSegments.length === tokenUrlList.length && reversedMatchSegments.length === appUrlList.length) {
      return true;
    }

    // Quick match TLD assuming TLD is only one path part
    if (reversedMatchSegments.length > 1) {
      return true;
    }

    return false;
  }

  /**
   * @description Gets the user's profile data and returns it if it exists. Should be called after {@link userSessionExists} or it will be empty.
   * @return {Object} The user data object.
   */
  getUserIdentity() {
    // Implementor's Note: Do not log in this method as it is frequently called from loggers and therefore would introduce an infinite loop.

    const idToken = userIdentityTokenStorageManager.getUserCookie();
    // Cache the ID Token in the local storage as soon as we attempt to check for it.
    // * We need this in the cache, and the best way to do this is right here, so it's in one place
    // * While this isn't the optimal location, this will ensure that every fetch to the user identity correctly is cached and is returned to the caller.
    const userDataFromCookie = jwtManager.decodeOrParse(idToken);
    if (userDataFromCookie) {
      const expiry = userDataFromCookie.exp ? new Date(userDataFromCookie.exp * 1000) : new Date(Date.now() + 86400000);
      userIdentityTokenStorageManager.set(idToken, expiry);
      userDataFromCookie.userId = userDataFromCookie.sub;
      return userDataFromCookie;
    }

    const userIdToken = userIdentityTokenStorageManager.get();
    const userData = jwtManager.decodeOrParse(userIdToken);
    if (!userData) {
      return null;
    }

    // We use endsWith because the issuer will be limited to only the authress custom domain FQDN subdomain, the hostUrl could be a specific subdomain subdomain for the tenant.
    // * issuer = tenant.custom.domain, hostUrl = custom.domain => ✓
    // * issuer = accountId.login.authress.io, hostUrl = login.authress.io => ✓

    const issuerOrigin = new URL(userData.iss).hostname;
    const hostUrlOrigin = new URL(this.hostUrl).hostname;
    if (!issuerOrigin.endsWith(hostUrlOrigin) && !hostUrlOrigin.endsWith(issuerOrigin)) {
      userIdentityTokenStorageManager.clear();
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

  async getDevices() {
    try {
      const token = await this.ensureToken();
      const deviceResult = await this.httpClient.get('/session/devices', this.enableCredentials, { Authorization: token && `Bearer ${token}` });
      return deviceResult.data.devices;
    } catch (error) {
      return [];
    }
  }

  async deleteDevice(deviceId) {
    try {
      const token = await this.ensureToken();
      await this.httpClient.delete(`/session/devices/${encodeURIComponent(deviceId)}`, this.enableCredentials, { Authorization: token && `Bearer ${token}` });
    } catch (error) {
      this.logger && this.logger.log({ title: '[Authress Login SDK] Failed to delete device', error });
      throw error;
    }
  }

  async openUserConfigurationScreen(options = { redirectUrl: null, startPage: 'Profile' }) {
    if (!await this.userSessionExists()) {
      const e = Error('User must be logged to configure user profile data.');
      e.code = 'NotLoggedIn';
      throw e;
    }

    const userConfigurationScreenUrl = new URL('/settings', this.hostUrl);
    userConfigurationScreenUrl.searchParams.set('client_id', this.applicationId);
    userConfigurationScreenUrl.searchParams.set('start_page', options && options.startPage || 'Profile');
    userConfigurationScreenUrl.searchParams.set('redirect_uri', options && options.redirectUrl || windowManager.getCurrentLocation().href);
    windowManager.assign(userConfigurationScreenUrl.toString());
    await Promise.resolve();
  }

  async registerDevice(options = { name: '', type: '', totp: {} }) {
    const userIdentity = await this.getUserIdentity();
    if (!userIdentity) {
      const e = Error('User must be logged to configure user profile data.');
      e.code = 'NotLoggedIn';
      throw e;
    }

    if (!options) {
      const e = Error("Register Device missing required parameter: 'Options'");
      e.code = 'InvalidInput';
      throw e;
    }

    let request;
    if (!options.type || options.type === 'WebAuthN') {
      const userId = userIdentity.sub;

      // https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/create
      // Development Note: To actually test to see if this works on your local development machine, run this code on an https domain in the Web Inspector Console tab.
      const publicKeyCredentialCreationOptions = {
        challenge: Uint8Array.from(userId, c => c.charCodeAt(0)),
        rp: {
          // Allow all subdomains, this works because Authress always runs on a subdomain such as login.example.com, where the domain example.com is owned by the authress account owner.
          id: this.hostUrl.split('.').slice(1).join('.'),
          name: 'WebAuthN Login'
        },
        user: {
          id: Uint8Array.from(userId, c => c.charCodeAt(0)),
          name: userId,
          displayName: `Generated User ID: ${userId}`
        },
        // https://www.iana.org/assignments/cose/cose.xhtml#algorithms (Order Matters)
        pubKeyCredParams: [
          // Disabled in the library and not currently supported
          // { type: 'public-key', alg: -8 }, /* EdDSA */
          // { type: 'public-key', alg: -36 }, /* ES512 */
          // { type: 'public-key', alg: -35 }, /* ES384 */
          { type: 'public-key', alg: -7 }, /* ES256 */
          // { type: 'public-key', alg: -39 }, /* PS512 */
          // { type: 'public-key', alg: -38 }, /* PS384 */
          // { type: 'public-key', alg: -37 }, /* PS256 */
          // { type: 'public-key', alg: -259 }, /* RS512 */
          // { type: 'public-key', alg: -258 }, /* RS384 */
          { type: 'public-key', alg: -257 } /* RS256 */
        ],
        authenticatorSelection: {
          residentKey: 'discouraged',
          requireResidentKey: false,
          userVerification: 'discouraged'
          // authenticatorAttachment: 'cross-platform'
        },
        timeout: 60000,
        attestation: 'direct'
      };

      const credential = await navigator.credentials.create({
        publicKey: publicKeyCredentialCreationOptions
      });

      const webAuthNTokenRequest = {
        authenticatorAttachment: credential.authenticatorAttachment,
        credentialId: credential.id,
        type: credential.type,
        userId: userId,
        attestation: btoa(String.fromCharCode(...new Uint8Array(credential.response.attestationObject))),
        client: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON)))
      };

      request = {
        name: options && options.name,
        code: webAuthNTokenRequest,
        type: 'WebAuthN'
      };
    } else if (options.type === 'TOTP') {
      request = {
        name: options.name,
        code: options.totp.verificationCode,
        totpData: options.totp,
        type: 'TOTP'
      };
    }

    try {
      const token = await this.ensureToken();
      const deviceCreationResult = await this.httpClient.post('/session/devices', this.enableCredentials, request, { Authorization: token && `Bearer ${token}` });
      return deviceCreationResult.data;
    } catch (error) {
      this.logger && this.logger.log({ title: '[Authress Login SDK] Failed to register new device', error, request });
      throw error;
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
   * @description Checks if the user's auth session is still valid, meaning they are still logged in, even if their current access token is expired. This will make an API call to Authress to validate their current auth session. Recommendation: Call this function on every route change.
   * @return {Promise<Boolean>} Returns truthy if there a valid existing session, falsy otherwise.
   */
  userSessionExists(backgroundTrigger) {
    // Prevent duplicate calls to checking the user session when they happen within the same 50ms time span
    if (Date.now() - this.lastSessionCheck < 50) {
      return userSessionSequencePromise;
    }

    // Or if one is already in progress
    if (userSessionCheckIsInProgress) {
      return userSessionSequencePromise;
    }

    // These can be set here because the single threaded nature, there is no way that userSessionCheckIsInProgress can be true, but the userSessionSequencePromise to not have been updated. So we don't need any complex locking here, which javascript does not even support
    this.lastSessionCheck = Date.now();
    userSessionCheckIsInProgress = true;

    return userSessionSequencePromise = userSessionSequencePromise
    .catch(() => { /* ignore since we always want to continue even after a failure */ })
    .then(async () => {
      try {
        const result = await this.userSessionContinuation(backgroundTrigger);
        userSessionCheckIsInProgress = false;
        return result;
      } catch (error) {
        userSessionCheckIsInProgress = false;
        throw error;
      }
    });
  }

  async userSessionContinuation(backgroundTrigger) {
    const urlSearchParams = new URLSearchParams(windowManager.getCurrentLocation().search);

    let authRequest = {};
    if (typeof localStorage !== 'undefined') {
      try {
        authRequest = JSON.parse(localStorage.getItem(AuthenticationRequestNonceKey) || '{}');
        localStorage.removeItem(AuthenticationRequestNonceKey);
        if (Object.hasOwnProperty.call(authRequest, 'enableCredentials')) {
          this.enableCredentials = authRequest.enableCredentials;
        }
      } catch (error) {
        this.logger && this.logger.debug && this.logger.debug({ title: '[Authress Login SDK] LocalStorage failed in Browser', error });
      }
    }

    // Your app was redirected to from the Authress Hosted Login page. The next step is to show the user the login widget and enable them to login.
    if (urlSearchParams.get('state') && urlSearchParams.get('flow') === 'oauthLogin') {
      return false;
    }

    // We are in the Authress authentication context. We might not have a code and we might not have other properties depending on the login path, so this check let's us ensure we delete all url parameters that aren't necessary, and since this will happen even outside of an auth exchange, let's also check for containing the matching iss
    if (authRequest.nonce || urlSearchParams.get('iss') && urlSearchParams.get('iss').includes(this.hostUrl)) {
      this.sanitizeQueryParameters();
    }

    if (authRequest.nonce && urlSearchParams.get('code')) {
      // Compare the initial authentication requestId to the returned one. If they don't match either the nonce has been tampered with or this isn't the latest authentication request
      // * This prevents canonical replay attacks, and fall through. If the user is already logged in, then the new log in attempt is ignored.
      if (authRequest.nonce === urlSearchParams.get('nonce')) {
        const code = urlSearchParams.get('code') === 'cookie' ? cookieManager.parse(document.cookie)['auth-code'] : urlSearchParams.get('code');
        const antiAbuseHash = await jwtManager.calculateAntiAbuseHash({ client_id: this.applicationId, authenticationRequestId: authRequest.nonce, code });
        const request = { grant_type: 'authorization_code', redirect_uri: authRequest.redirectUrl, client_id: this.applicationId, code, code_verifier: authRequest.codeVerifier, antiAbuseHash };
        try {
          const tokenResult = await this.httpClient.post(`/authentication/${authRequest.nonce}/tokens`, this.enableCredentials, request);
          const idToken = jwtManager.decode(tokenResult.data.id_token);
          const expiry = idToken.exp && new Date(idToken.exp * 1000) || tokenResult.data.expires_in && new Date(Date.now() + tokenResult.data.expires_in * 1000);
          document.cookie = cookieManager.serialize('authorization', tokenResult.data.access_token || '', { expires: expiry, path: '/', sameSite: 'strict' });
          userIdentityTokenStorageManager.set(tokenResult.data.id_token, expiry);
          userSessionResolver();
          return true;
        } catch (error) {
          this.logger && this.logger.log({ title: '[Authress Login SDK] Failed exchange authentication response for a token.', error });

          // The code was expired, contaminated, or already exchanged.
          if (error.data && error.data.error === 'invalid_request') {
            return false;
          }
          throw (error.data || error);
        }
      }
    }

    if (windowManager.isLocalHost()) {
      if (urlSearchParams.get('nonce') && urlSearchParams.get('access_token')) {
        // Compare the initial authentication requestId to the returned one. If they don't match either the nonce has been tampered with or this isn't the latest authentication request
        // * This prevents canonical replay attacks, and fall through. If the user is already logged in, then the new log in attempt is ignored.
        if (!authRequest.nonce || authRequest.nonce === urlSearchParams.get('nonce')) {
          const idToken = jwtManager.decode(urlSearchParams.get('id_token'));
          const expiry = idToken.exp && new Date(idToken.exp * 1000) || Number(urlSearchParams.get('expires_in')) && new Date(Date.now() + Number(urlSearchParams.get('expires_in')) * 1000);
          document.cookie = cookieManager.serialize('authorization', urlSearchParams.get('access_token') || '', { expires: expiry, path: '/', sameSite: 'strict' });
          userIdentityTokenStorageManager.set(urlSearchParams.get('id_token'), expiry);
          userSessionResolver();
          return true;
        }
      }
      // Otherwise check cookies and then force the user to log in
    }

    // At this point the user identity should have been loaded through cookies (if the cookie mechanism was selected and it isn't local host.) So we'll first check if a login session just completed.
    const userData = this.getUserIdentity();
    // User is already logged in
    if (userData) {
      userSessionResolver();
      return true;
    }

    if (!windowManager.isLocalHost() && !backgroundTrigger) {
      try {
        const sessionResult = await this.httpClient.patch('/session', this.enableCredentials, {}, null, true);
        // In the case that the session contains non cookie based data, store it back to the cookie for this domain
        if (sessionResult.data.access_token) {
          const idToken = jwtManager.decode(sessionResult.data.id_token);
          const expiry = idToken.exp && new Date(idToken.exp * 1000) || sessionResult.data.expires_in && new Date(Date.now() + sessionResult.data.expires_in * 1000);
          document.cookie = cookieManager.serialize('authorization', sessionResult.data.access_token || '', { expires: expiry, path: '/', sameSite: 'strict' });
          userIdentityTokenStorageManager.set(sessionResult.data.id_token, expiry);
        }
      } catch (error) {
        // On 400, 404, 409 we know that the session is no longer able to be continued.
        if (error.status === 400 || error.status === 404 || error.status === 409) {
          this.logger && this.logger.log && this.logger.log({ title: '[Authress Login SDK] User does not have an existing authentication session', error });
        } else {
          this.logger && this.logger.log && this.logger.log({ title: '[Authress Login SDK] Failed attempting to check if the user has an existing authentication session', error });
        }
      }
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
   * @description When a platform extension attempts to log a user in, the Authress Login page will redirect to your Platform defaultAuthenticationUrl. At this point, show the user the login screen, and then pass the results of the login to this method.
   * @param {String} [state] The redirect to your login screen will contain two query parameters `state` and `flow`. Pass the state into this method.
   * @param {String} [connectionId] Specify which provider connection that user would like to use to log in - see https://authress.io/app/#/manage?focus=connections
   * @param {String} [tenantLookupIdentifier] Instead of connectionId, specify the tenant lookup identifier to log the user with the mapped tenant - see https://authress.io/app/#/manage?focus=tenants
   * @param {Object} [connectionProperties] Connection specific properties to pass to the identity provider. Can be used to override default scopes for example.
   * @return {Promise<AuthenticateResponse | null>} The authentication response.
   */
  async updateExtensionAuthenticationRequest({ state, connectionId, tenantLookupIdentifier, connectionProperties }) {
    if (!connectionId && !tenantLookupIdentifier) {
      const e = Error('connectionId or tenantLookupIdentifier must be specified');
      e.code = 'InvalidConnection';
      throw e;
    }

    const urlSearchParams = new URLSearchParams(windowManager.getCurrentLocation().search);
    const authenticationRequestId = state || urlSearchParams.get('state');
    if (!authenticationRequestId) {
      const e = Error('The `state` parameters must be specified to update this authentication request');
      e.code = 'InvalidAuthenticationRequest';
      throw e;
    }

    try {
      const antiAbuseHash = await jwtManager.calculateAntiAbuseHash({ connectionId, tenantLookupIdentifier, authenticationRequestId });
      const requestOptions = await this.httpClient.patch(`/authentication/${authenticationRequestId}`, true, {
        antiAbuseHash,
        connectionId, tenantLookupIdentifier, connectionProperties
      });

      // If authenticate is called from inside the custom login screen then instead return the redirect url and let the caller deal with it. That is, if the federated login provider is the same as the current UI, there is no need to do anything special.
      if (new URL(requestOptions.data.authenticationUrl).hostname === windowManager.getCurrentLocation().hostname) {
        return {
          authenticationUrl: requestOptions.data.authenticationUrl
        };
      }

      windowManager.assign(requestOptions.data.authenticationUrl);
    } catch (error) {
      this.logger && this.logger.log && this.logger.log({ title: '[Authress Login SDK] Failed to update extension authentication request', error });
      if (error.status && error.status >= 400 && error.status < 500) {
        const e = Error(error.data && (error.data.title || error.data.errorCode) || error.data || 'Unknown Error');
        e.code = error.data && error.data.errorCode;
        throw e;
      }
      throw (error.data || error);
    }

    // Prevent the current UI from taking any action once we decided we need to log in.
    await new Promise(resolve => setTimeout(resolve, 5000));
    return null;
  }

  /**
   * @description Unlink an identity from the user's account.
   * @param {String} identityId Specify the provider connection id or the user id of that connection that user would like to unlink - see https://authress.io/app/#/manage?focus=connections
   * @return {Promise<void>} Throws an error if identity cannot be unlinked.
   */
  async unlinkIdentity(identityId) {
    if (!identityId) {
      const e = Error('connectionId must be specified');
      e.code = 'InvalidConnection';
      throw e;
    }

    if (!this.getUserIdentity()) {
      const e = Error('User must be logged in to unlink an account.');
      e.code = 'NotLoggedIn';
      throw e;
    }

    let accessToken;
    try {
      accessToken = await this.ensureToken({ timeoutInMillis: 100 });
    } catch (error) {
      if (error.code === 'TokenTimeout') {
        const e = Error('User must be logged into an existing account before linking a second account.');
        e.code = 'NotLoggedIn';
        throw e;
      }
    }

    const headers = this.enableCredentials && !windowManager.isLocalHost() ? {} : {
      Authorization: `Bearer ${accessToken}`
    };

    try {
      await this.httpClient.delete(`/identities/${encodeURIComponent(identityId)}`, this.enableCredentials, headers);
    } catch (error) {
      this.logger && this.logger.log && this.logger.log({ title: '[Authress Login SDK] Failed to unlink user identity', error });
      if (error.status && error.status >= 400 && error.status < 500) {
        const e = Error(error.data && (error.data.title || error.data.errorCode) || error.data || 'Unknown Error');
        e.code = error.data && error.data.errorCode;
        throw e;
      }
      throw (error.data || error);
    }
  }

  /**
   * @description Link a new identity to the currently logged in user. The user will be asked to authenticate to a new connection.
   * @param {String} [connectionId] Specify which provider connection that user would like to use to log in - see https://authress.io/app/#/manage?focus=connections
   * @param {String} [tenantLookupIdentifier] Instead of connectionId, specify the tenant lookup identifier to log the user with the mapped tenant - see https://authress.io/app/#/manage?focus=tenants
   * @param {String} [redirectUrl=${window.location.href}] Specify where the provider should redirect to the user to in your application. If not specified, the default is the current location href. Must be a valid redirect url matching what is defined in the application in the Authress Management portal.
   * @param {Object} [connectionProperties] Connection specific properties to pass to the identity provider. Can be used to override default scopes for example.
   * @return {Promise<void>} Is there a valid existing session.
   */
  async linkIdentity({ connectionId, tenantLookupIdentifier, redirectUrl, connectionProperties }) {
    if (!connectionId && !tenantLookupIdentifier) {
      const e = Error('connectionId or tenantLookupIdentifier must be specified');
      e.code = 'InvalidConnection';
      throw e;
    }

    if (!this.getUserIdentity()) {
      const e = Error('User must be logged into an existing account before linking a second account.');
      e.code = 'NotLoggedIn';
      throw e;
    }

    let accessToken;
    try {
      accessToken = await this.ensureToken({ timeoutInMillis: 100 });
    } catch (error) {
      if (error.code === 'TokenTimeout') {
        const e = Error('User must be logged into an existing account before linking a second account.');
        e.code = 'NotLoggedIn';
        throw e;
      }
    }

    const { codeChallenge } = await jwtManager.getAuthCodes();
    const antiAbuseHash = await jwtManager.calculateAntiAbuseHash({ connectionId, tenantLookupIdentifier, applicationId: this.applicationId });

    try {
      const normalizedRedirectUrl = redirectUrl && new URL(redirectUrl).toString();
      const selectedRedirectUrl = normalizedRedirectUrl || windowManager.getCurrentLocation().href;
      const headers = this.enableCredentials && !windowManager.isLocalHost() ? {} : {
        Authorization: `Bearer ${accessToken}`
      };
      const requestOptions = await this.httpClient.post('/authentication', this.enableCredentials, {
        antiAbuseHash,
        linkIdentity: true,
        redirectUrl: selectedRedirectUrl, codeChallengeMethod: 'S256', codeChallenge,
        connectionId, tenantLookupIdentifier,
        connectionProperties,
        applicationId: this.applicationId
      }, headers);
      windowManager.assign(requestOptions.data.authenticationUrl);
    } catch (error) {
      this.logger && this.logger.log && this.logger.log({ title: '[Authress Login SDK] Failed to start user identity link', error });
      if (error.status && error.status >= 400 && error.status < 500) {
        const e = Error(error.data && (error.data.title || error.data.errorCode) || error.data || 'Unknown Error');
        e.code = error.data && error.data.errorCode;
        throw e;
      }
      throw error;
    }

    // Prevent the current UI from taking any action once we decided we need to log in.
    await new Promise(resolve => setTimeout(resolve, 5000));
  }

  /**
   * @description Logs a user in, if the user is not logged in, will begin the passwordless flow as documented at: https://authress.io/knowledge-base/docs/authentication/connecting-providers-idp/oauth-setup-guide-part-3, then redirect back to the {@link redirectUrl}.
   * @param {String} [serviceClientId] Specify which service client will be used to complete the passwordless authentication.
   * @param {String} [inviteId] Invite to use to login, only one of the connectionId, tenantLookupIdentifier, or the inviteId is required.
   * @param {String} [responseLocation=cookie] Store the credentials response in the specified location. Options are either 'cookie' or 'query'.
   * @param {String} [flowType=token id_token] The type of credentials returned in the response. The list of options is any of 'code token id_token' separated by a space. Select token to receive an access_token, id_token to return the user identity in an JWT, and code for the authorization_code grant_type flow.
   * @param {String} [redirectUrl=${window.location.href}] Specify where the provider should redirect to the user to in your application. If not specified, the default is the current location href. Must be a valid redirect url matching what is defined in the application in the Authress Management portal.
   * @param {Boolean} [force=false] Force getting new credentials.
   * @param {Boolean} [clearUserDataBeforeLogin=true] Remove all cookies, LocalStorage, and SessionStorage related data before logging in. In most cases, this helps prevent corrupted browser state from affecting your user's experience.
   * @return {Promise<AuthenticateResponse | null>} The authentication response.
   */
  async authenticateWithOneTimeCode(options = {}) {
    const { serviceClientId, inviteId, redirectUrl, force, responseLocation, flowType, clearUserDataBeforeLogin } = (options || {});
    if (responseLocation && responseLocation !== 'cookie' && responseLocation !== 'query' && responseLocation !== 'none') {
      const e = Error('Authentication response location is not valid');
      e.code = 'InvalidResponseLocation';
      throw e;
    }

    if (!serviceClientId) {
      const e = Error('The Passwordless Service Client ID is required');
      e.code = 'InvalidInput';
      throw e;
    }

    // We include inviteId here because inviteId also allow linking to tenants and capturing groups and access records associated with the invite
    if (!inviteId && !force && await this.userSessionExists()) {
      const existingJwtTokenString = await this.ensureToken();
      const jwtPayload = jwtManager.decode(existingJwtTokenString);
      if (jwtPayload && jwtPayload.azp && serviceClientId !== jwtPayload.azp) {
        this.logger && this.logger.log && this.logger.log({ title: '[Authress Login SDK] Authentication blocked because the user is already logged in, and the requested authentication parameters do not match the original session.', requestedAuthenticationOptions: options, currentAuthenticationSessionData: jwtPayload });
        const e = Error(`Authentication requested for user that is already logged in, but the connectionId specified does not match their existing session.
        Recommended Options:
          (1) If the goal is to force them to log in with this new connection and ignore their existing session, use the "force" flag.
          (2) If the goal is link their current identity with a new from the new connection, use the linkIdentity() method.
          (3) If the goal is skip log in if they are already logged in or force log in with the connectionId, first check if userSessionExists() and then only if "false", call authenticate().`);
        e.code = 'AuthenticationConstraintContention';
        throw e;
      }

      return null;
    }

    const { codeVerifier, codeChallenge } = await jwtManager.getAuthCodes();
    const antiAbuseHash = await jwtManager.calculateAntiAbuseHash({ serviceClientId, inviteId, applicationId: this.applicationId });

    try {
      const normalizedRedirectUrl = redirectUrl && new URL(redirectUrl).toString();
      const selectedRedirectUrl = normalizedRedirectUrl || windowManager.getCurrentLocation().href;
      if (clearUserDataBeforeLogin !== false) {
        userIdentityTokenStorageManager.clear();
      }

      const authResponse = await this.httpClient.post('/authentication', this.enableCredentials, {
        antiAbuseHash,
        redirectUrl: selectedRedirectUrl, codeChallengeMethod: 'S256', codeChallenge,
        connectionId: serviceClientId, inviteId,
        applicationId: this.applicationId,
        responseLocation, flowType
      });
      localStorage.setItem(AuthenticationRequestNonceKey, JSON.stringify({
        nonce: authResponse.data.authenticationRequestId, codeVerifier, lastConnectionId: serviceClientId, redirectUrl: selectedRedirectUrl,
        enableCredentials: authResponse.data.enableCredentials
      }));

      return {
        authenticationUrl: authResponse.data.authenticationUrl,
        authenticationRequestId: authResponse.data.authenticationRequestId
      };
    } catch (error) {
      this.logger && this.logger.log && this.logger.log({ title: '[Authress Login SDK] Failed to start authentication for user', error });
      if (error.status && error.status >= 400 && error.status < 500) {
        const e = Error(error.data && (error.data.title || error.data.errorCode) || error.data || 'Unknown Error');
        e.code = error.data && error.data.errorCode;
        throw e;
      }
      throw (error.data || error);
    }
  }

  /**
   * @description Logs a user in, if the user is not logged in, will redirect the user to their selected connection/provider and then redirect back to the {@link redirectUrl}.
   * @param {String} [connectionId] Specify which provider connection that user would like to use to log in - see https://authress.io/app/#/manage?focus=connections
   * @param {String} [tenantLookupIdentifier] Instead of connectionId, specify the tenant lookup identifier to log the user with the mapped tenant - see https://authress.io/app/#/manage?focus=tenants
   * @param {String} [inviteId] Invite to use to login, only one of the connectionId, tenantLookupIdentifier, or the inviteId is required.
   * @param {String} [responseLocation=cookie] Store the credentials response in the specified location. Options are either 'cookie' or 'query'.
   * @param {String} [flowType=token id_token] The type of credentials returned in the response. The list of options is any of 'code token id_token' separated by a space. Select token to receive an access_token, id_token to return the user identity in an JWT, and code for the authorization_code grant_type flow.
   * @param {String} [redirectUrl=${window.location.href}] Specify where the provider should redirect to the user to in your application. If not specified, the default is the current location href. Must be a valid redirect url matching what is defined in the application in the Authress Management portal.
   * @param {Object} [connectionProperties] Connection specific properties to pass to the identity provider. Can be used to override default scopes for example.
   * @param {Boolean} [force=false] Force getting new credentials.
   * @param {Boolean} [multiAccount=false] Enable multi-account login. The user will be prompted to login with their other account, if they are not logged in already.
   * @param {Boolean} [clearUserDataBeforeLogin=true] Remove all cookies, LocalStorage, and SessionStorage related data before logging in. In most cases, this helps prevent corrupted browser state from affecting your user's experience.
   * @return {Promise<AuthenticateResponse | null>} The authentication response.
   */
  async authenticate(options = {}) {
    const { connectionId, tenantLookupIdentifier, inviteId, redirectUrl, force, responseLocation, flowType, connectionProperties, openType, multiAccount, clearUserDataBeforeLogin } = (options || {});
    if (responseLocation && responseLocation !== 'cookie' && responseLocation !== 'query' && responseLocation !== 'none') {
      const e = Error('Authentication response location is not valid');
      e.code = 'InvalidResponseLocation';
      throw e;
    }

    // We include inviteId here because inviteId also allow linking to tenants and capturing groups and access records associated with the invite
    if (!inviteId && !force && !multiAccount && await this.userSessionExists()) {
      const existingJwtTokenString = await this.ensureToken();
      const jwtPayload = jwtManager.decode(existingJwtTokenString);
      if (connectionId && jwtPayload && jwtPayload.azp && connectionId !== jwtPayload.azp) {
        this.logger && this.logger.log && this.logger.log({ title: '[Authress Login SDK] Authentication blocked because the user is already logged in, and the requested authentication parameters do not match the original session.', requestedAuthenticationOptions: options, currentAuthenticationSessionData: jwtPayload });
        const e = Error(`Authentication requested for user that is already logged in, but the connectionId specified does not match their existing session.
        Recommended Options:
          (1) If the goal is to force them to log in with this new connection and ignore their existing session, use the "force" flag.
          (2) If the goal is link their current identity with a new from the new connection, use the linkIdentity() method.
          (3) If the goal is skip log in if they are already logged in or force log in with the connectionId, first check if userSessionExists() and then only if "false", call authenticate().`);
        e.code = 'AuthenticationConstraintContention';
        throw e;
      }

      return null;
    }

    const { codeVerifier, codeChallenge } = await jwtManager.getAuthCodes();
    const antiAbuseHash = await jwtManager.calculateAntiAbuseHash({ connectionId, tenantLookupIdentifier, inviteId, applicationId: this.applicationId });

    try {
      const normalizedRedirectUrl = redirectUrl && new URL(redirectUrl).toString();
      const selectedRedirectUrl = normalizedRedirectUrl || windowManager.getCurrentLocation().href;
      if (clearUserDataBeforeLogin !== false) {
        userIdentityTokenStorageManager.clear();
      }

      // this.enableCredentials must be false as long as the response from the Authress Token Service do not include access-control-allow-credentials: true in the response to errors
      const authResponse = await this.httpClient.post('/authentication', false, {
        antiAbuseHash,
        redirectUrl: selectedRedirectUrl, codeChallengeMethod: 'S256', codeChallenge,
        connectionId, tenantLookupIdentifier, inviteId,
        connectionProperties,
        applicationId: this.applicationId,
        responseLocation, flowType, multiAccount
      });
      localStorage.setItem(AuthenticationRequestNonceKey, JSON.stringify({
        nonce: authResponse.data.authenticationRequestId, codeVerifier, lastConnectionId: connectionId, tenantLookupIdentifier, redirectUrl: selectedRedirectUrl,
        enableCredentials: authResponse.data.enableCredentials, multiAccount
      }));

      // If authenticate is called from inside the custom login screen then instead return the redirect url and let the caller deal with it. That is, if the federated login provider is the same as the current UI, there is no need to do anything special.
      if (new URL(authResponse.data.authenticationUrl).hostname === windowManager.getCurrentLocation().hostname) {
        return {
          authenticationUrl: authResponse.data.authenticationUrl,
          authenticationRequestId: authResponse.data.authenticationRequestId
        };
      }

      if (openType === 'tab') {
        const result = windowManager.open(authResponse.data.authenticationUrl, '_blank');
        if (!result || result.closed || typeof result.closed === 'undefined') {
          windowManager.assign(authResponse.data.authenticationUrl);
        }
      } else {
        windowManager.assign(authResponse.data.authenticationUrl);
      }
    } catch (error) {
      this.logger && this.logger.log && this.logger.log({ title: '[Authress Login SDK] Failed to start authentication for user', error });
      if (error.status && error.status >= 400 && error.status < 500) {
        const e = Error(error.data && (error.data.title || error.data.errorCode) || error.data || 'Unknown Error');
        e.code = error.data && error.data.errorCode;
        throw e;
      }
      throw (error.data || error);
    }

    // Prevent the current UI from taking any action once we decided we need to log in.
    await new Promise(resolve => setTimeout(resolve, 5000));
    return null;
  }

  /**
   * @description Ensures the user's bearer token exists. To be used in the Authorization header as a Bearer token. This method blocks on a valid user session being created, and expects {@link authenticate} to have been called first. Additionally, if the application configuration specifies that tokens should be secured from javascript, the token will be a hidden cookie only visible to service APIs and will not be returned. If the token is expired and the session is still valid, then it will automatically generate a new token directly from Authress.
   * @param {Object} [options] Options for getting a token including timeout configuration.
   * @param {Number} [options.timeoutInMillis=5000] Timeout waiting for user token to populate. After this time an error will be thrown.
   * @return {Promise<String>} The Authorization Bearer token
   * @throws {TokenTimeout} After the timeout if no session was found. By default waits for 5000 for another thread to continue the session, after which if still no token exists, will throw
   */
  async ensureToken(options) {
    // When the time is set to zero, don't race the promises, instead just directly check if the token likely exists and return it. Otherwise throw.
    // * We do this to avoid a scenario where the Promise.race(setTimeout(0)) immediately returns first even if the session is available.
    if (options && options.timeoutInMillis === 0) {
      const userIdentity = this.getUserIdentity();
      const cookies = cookieManager.parse(document.cookie);
      if (userIdentity) {
        return cookies.authorization !== 'undefined' && cookies.authorization;
      }

      const error = Error('No token retrieved after timeout');
      error.code = 'TokenTimeout';
      throw error;
    }

    // This isn't strictly required, but firing it off, puts the session in waiting until we get confirmation back, that means that the next part will block on waiting sessions
    // * We could delegate calling this to the application, but it's possible for them to get that wrong, instead, all requests to userSessionExists will be collapsed and ensure only one is run in serial. This has the secondary benefit of avoiding multiple token exchanges and accidentally race-condition on multiple exchanges of the same auth session token.
    await this.userSessionExists();

    // Timeout after the timeout so that all threads don't "get stuck" in an unexpected way for consumers of the library.
    const inputOptions = Object.assign({ timeoutInMillis: 5000 }, options || {});
    const sessionWaiterAsync = this.waitForUserSession();

    // The max timeout is -1 or Infinity, however `setTimeout` does really like that, often the max allowed value is 2**31 - 1 (MAX_INT), so we'll use that instead
    // https://developer.mozilla.org/en-US/docs/Web/API/setTimeout#maximum_delay_value
    const timeoutInMillis = inputOptions.timeoutInMillis === -1 || inputOptions.timeoutInMillis > (2 ** 31 - 1) ? (2 ** 31 - 1) : inputOptions.timeoutInMillis;

    const timeoutAsync = new Promise((resolve, reject) => setTimeout(reject, timeoutInMillis || 0));
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

  /**
   * @description Log the user out removing the current user's session. If the user is not logged in this has no effect. If the user is logged in via secure session, the the redirect url will be ignored. If the user is logged in without a secure session the user agent will be redirected to the hosted login and then redirected to the {@link redirectUrl}.
   * @param {String} [redirectUrl='window.location.href'] Optional redirect location to return the user to after logout. Will only be used for cross domain sessions.
   * @throws InvalidRedirectUrl - When the passed in redirect url is not a valid url.
   */
  async logout(requestedRedirectUrl) {
    let redirectUrl;
    if (requestedRedirectUrl) {
      try {
        // eslint-disable-next-line no-new
        new URL(requestedRedirectUrl);
        redirectUrl = requestedRedirectUrl;
      } catch (error) {
        try {
          redirectUrl = new URL(requestedRedirectUrl, windowManager.getCurrentLocation().href).toString();
        } catch (relativeRedirectUrlAlsoFailed) {
          const e = Error(`The logout redirect url is not valid URL: ${requestedRedirectUrl}`);
          e.code = 'InvalidRedirectUrl';
          throw e;
        }
      }
    }

    userIdentityTokenStorageManager.clear();

    // Terminate all query parameters in the URL which might trick the app into thinking that the user is still logged in. Any property that is associated with Authress should be removed.
    this.sanitizeQueryParameters();

    // Reset user local session
    userSessionPromise = new Promise(resolve => userSessionResolver = resolve);
    if (this.enableCredentials) {
      try {
        await this.httpClient.delete('/session', this.enableCredentials);
        this.lastSessionCheck = 0;
        // We use the requestedRedirectUrl here and not the redirectUrl because `windowManager.assign` actually accepts relative urls
        // * AND we don't want to force a navigation if we are already in the right location.
        if (requestedRedirectUrl && requestedRedirectUrl !== windowManager.getCurrentLocation().href) {
          windowManager.assign(requestedRedirectUrl);
        }
        return;
      } catch (error) { /**/ }
    }

    const fullLogoutUrl = new URL('/logout', this.hostUrl);
    fullLogoutUrl.searchParams.set('redirect_uri', redirectUrl || windowManager.getCurrentLocation().href);
    fullLogoutUrl.searchParams.set('client_id', this.applicationId);
    windowManager.assign(fullLogoutUrl.toString());

    this.lastSessionCheck = 0;

    // Prevent the current UI from taking any action once we decided we need to log out.
    await new Promise(resolve => setTimeout(resolve, 500));
  }

  sanitizeQueryParameters() {
    const newUrl = new URL(windowManager.getCurrentLocation());
    newUrl.searchParams.delete('iss');
    newUrl.searchParams.delete('nonce');
    newUrl.searchParams.delete('code');
    newUrl.searchParams.delete('expires_in');
    newUrl.searchParams.delete('access_token');
    newUrl.searchParams.delete('id_token');
    history.replaceState({}, undefined, newUrl.toString());
  }
}

const ExtensionClient = require('./extensionClient');

const UserConfigurationScreen = {
  Profile: 'Profile',
  MFA: 'MFA'
};

module.exports = { LoginClient, ExtensionClient, UserConfigurationScreen };
