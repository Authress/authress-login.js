const jwtManager = require('./jwtManager');
const { sanitizeUrl } = require('./util');
const windowManager = require('./windowManager');

const AuthenticationRequestNonceKey = 'ExtensionRequestNonce';

let userSessionSequencePromise = null;

class ExtensionClient {
  /**
   * @constructor constructs an ExtensionClient to be embedded in your platform SDK to enable extension easy login
   * @param {string} authressCustomDomain Your Authress custom domain - see https://authress.io/app/#/manage?focus=domain
   * @param {string} extensionId The platform extensionId for this app - see https://authress.io/app/#/manage?focus=extensions
   */
  constructor(authressCustomDomain, extensionId) {
    this.extensionId = extensionId;

    if (!authressCustomDomain) {
      throw Error('Missing required property "authressCustomDomain" in ExtensionClient constructor. The Custom Authress Domain Host is required.');
    }

    if (!extensionId) {
      throw Error('Missing required property "extensionId" in ExtensionClient constructor. The extension is required for selecting the correct login method.');
    }

    this.authressCustomDomain = sanitizeUrl(authressCustomDomain);
    this.accessToken = null;

    windowManager.onLoad(async () => {
      await this.requestToken({ silent: true });
    });
  }

  /**
   * @description Gets the user's profile data and returns it if it exists. Should be called after {@link userSessionExists} or it will be empty.
   * @return {Promise<Record<string, unknown>>} The user data object.
   */
  async getUserIdentity() {
    const userData = this.accessToken && await jwtManager.decode(this.accessToken);
    if (!userData) {
      return null;
    }

    if (userData.exp * 1000 < Date.now()) {
      this.accessToken = null;
      return null;
    }

    return userData;
  }

  async getTokenResponse() {
    const isLoggedIn = await this.getUserIdentity();
    if (!isLoggedIn) {
      return null;
    }

    return { accessToken: this.accessToken };
  }

  /**
   * @description When a platform extension attempts to log a user in, the Authress Login page will redirect to your Platform defaultAuthenticationUrl. At this point, show the user the login screen, and then pass the results of the login to this method.
   * @param {String} [options.code] The redirect to your login screen will contain two query parameters `state` and `flow`. Pass the state into this method.
   * @return {Promise<TokenResponse>} Returns the token if the user is logged in otherwise redirects the user
   */
  requestToken(options = { code: null, silent: false }) {
    if (userSessionSequencePromise) {
      return userSessionSequencePromise = userSessionSequencePromise
      .catch(() => { /* ignore since we always want to continue even after a failure */ })
      .then(() => this.requestTokenContinuation(options));
    }
    const nextContinuation = this.requestTokenContinuation(options);
    nextContinuation.catch(() => { /* This prevents an uncaught promise rejection in the running process */ });
    return userSessionSequencePromise = nextContinuation;
  }

  async requestTokenContinuation(options = { code: null, silent: false }) {
    const code = options && options.code || new URLSearchParams(windowManager.getCurrentLocation().search).get('code');
    if (!code) {
      if (!options || !options.silent) {
        const e = Error('OAuth Authorization code is required');
        e.code = 'InvalidAuthorizationCode';
        throw e;
      }
      return this.getTokenResponse();
    }

    const url = new URL(this.authressCustomDomain);
    url.pathname = '/api/authentication/oauth/tokens';
    const { codeVerifier, redirectUrl } = JSON.parse(localStorage.getItem(AuthenticationRequestNonceKey) || '{}');
    const result = await fetch(url.toString(), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        code_verifier: codeVerifier,
        code,
        grant_type: 'authorization_code',
        client_id: this.extensionId,
        redirect_uri: redirectUrl
      })
    });

    const tokenResponse = await result.json();
    this.accessToken = tokenResponse.access_token;

    const newUrl = new URL(windowManager.getCurrentLocation());
    newUrl.searchParams.delete('code');
    newUrl.searchParams.delete('iss');
    newUrl.searchParams.delete('nonce');
    newUrl.searchParams.delete('expires_in');
    newUrl.searchParams.delete('access_token');
    newUrl.searchParams.delete('id_token');
    history.replaceState({}, undefined, newUrl.toString());

    return this.getTokenResponse();
  }

  /**
   * @description Logs a user in, if the user is logged in, will return the token response, if the user is not logged in, will redirect the user to their selected connection/provider and then redirect back to the {@link redirectUrl}.
   * @param {String} [redirectUrl=${window.location.href}] Specify where the provider should redirect to the user to in your application. If not specified, the default is the current location href. Must be a valid redirect url matching what is defined in the application in the Authress Management portal.
   * @return {Promise<TokenResponse>} Returns the token if the user is logged in otherwise redirects the user
   */
  async login(redirectUrlOverride) {
    const tokenResponse = await this.getTokenResponse();
    if (tokenResponse) {
      return tokenResponse;
    }
    const completeLoginResult = await this.requestToken({ silent: true });
    if (completeLoginResult) {
      return completeLoginResult;
    }
    const url = new URL(this.authressCustomDomain);

    const { codeVerifier, codeChallenge } = jwtManager.getAuthCodes();

    const redirectUrl = redirectUrlOverride || windowManager.getCurrentLocation().href;
    localStorage.setItem(AuthenticationRequestNonceKey, JSON.stringify({ codeVerifier, redirectUrl }));
    url.searchParams.set('client_id', this.extensionId);
    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');
    url.searchParams.set('redirect_uri', redirectUrl);
    windowManager.assign(url.toString());

    // Prevent the current UI from taking any action once we decided we need to log in.
    await new Promise(resolve => setTimeout(resolve, 5000));
    return null;
  }
}

module.exports = ExtensionClient;
