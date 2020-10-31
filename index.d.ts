/* eslint-disable @typescript-eslint/no-empty-interface */

export interface Settings {
  /** Your Authress custom domain - see https://authress.io/app/#/manage?focus=applications */
  authenticationServiceUrl: string;
  /** The Authress applicationId for this app - see https://authress.io/app/#/manage?focus=applications */
  applicationId: string;
}

export interface AuthenticationParameters {
  /** Specify which provider connection that user would like to use to log in - see https://authress.io/app/#/manage?focus=connections */
  connectionId: string;
  /** Specify where the provider should redirect to the user to in your application. If not specified with be the current location href. Must be a valid redirect url matching what is defined in the application in the Authress Management portal. (Default: **window.location.href**) */
  redirectUrl?: string;
  /** Force getting new credentials. (Default: **false** - only get new credentials if none exist.) */
  force?: boolean = false;
}

declare class LoginClient {
  /**
   * @constructor constructs the LoginClient with a given configuration
   * @param {Settings} settings Authress LoginClient settings
   * @param {Object} [logger] a configured logger object, optionally `console`, which can used to display debug and warning messages.
   */
  constructor(settings: Settings, logger?: Any): LoginClient;

  /**
   * @description Gets the user's profile data and returns it if it exists. Should be called after {@link userSessionExists} or it will be empty.
   * @return {Object} The user data object.
   */
  getUserData(): Any;

  /**
   * @description Async wait for a user session to exist. Will block until {@link userSessionExists} or {@link authenticate} is called.
   * @return {Promise<void>}
   */
  async waitForUserSession(): Promise<void>;

  /**
   * @description Call this function on every route change. It will check if the user just logged in or is still logged in.
   * @return {Promise<boolean>} Returns truthy if there a valid existing session, falsy otherwise.
   */
  async userSessionExists(): Promise<boolean>;

  /**
   * @description Logs a user in, if the user is not logged in, will redirect the user to their selected connection/provider and then redirect back to the {@link redirectUrl}.

   * @return {Promise<boolean>} Is there a valid existing session.
   */
  async authenticate(settings: AuthenticationParameters): Promise<boolean>;

  /**
   * @description Gets the user's bearer token to be used in the Authorization header as a Bearer token. This method blocks on a valid user session being created. So call after {@link userSessionExists}. Additionally, if the application configuration specifies that tokens should be secured from javascript, the token will be a hidden cookie only visible to service APIs and cannot be fetched from javascript.
   * @return {Promise<string>} The Authorization Bearer token.
   */
  async getToken(): Promise<string>;

  /**
   * @description Log the user out removing the current user's session
   */
  async logout(): Promise<void>;
}

export = { LoginClient };
