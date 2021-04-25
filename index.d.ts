interface Settings {
  /** Your Authress custom domain - see https://authress.io/app/#/manage?focus=applications */
  authressLoginHostUrl: string;
  /** The Authress applicationId for this app - see https://authress.io/app/#/manage?focus=applications */
  applicationId: string;
}

interface AuthenticationParameters {
  /** Specify which provider connection that user would like to use to log in - see https://authress.io/app/#/manage?focus=connections */
  connectionId?: string;
  /** Instead of connectionId, specify the tenant lookup identifier to log the user with the mapped tenant - see https://authress.io/app/#/manage?focus=tenants */
  tenantLookupIdentifier?: string;
  /** Store the credentials response in the specified location. Options are either 'cookie' or 'query'. (Default: **cookie**) */
  responseLocation: string;
  /** The type of credentials returned in the response. The list of options is any of 'code token id_token' separated by a space. Select token to receive an access_token, id_token to return the user identity in an JWT, and code for the authorization_code grant_type flow. (Default: **token id_token**) */
  flowType: string;
  /** Specify where the provider should redirect the user to in your application. If not specified, will be the current location href. Must be a valid redirect url matching what is defined in the application in the Authress Management portal. (Default: **window.location.href**) */
  redirectUrl?: string;
  /** Force getting new credentials. (Default: **false** - only get new credentials if none exist.) */
  force?: boolean;
}

/** Options for getting a token including timeout configuration. */
interface TokenParameters {
  /** Timeout waiting for user token to populate. After this time an error will be thrown. (Default: **5000**) */
  timeoutInMillis?: number;
}

export class LoginClient {
  /**
   * @constructor constructs the LoginClient with a given configuration
   * @param {Settings} settings Authress LoginClient settings
   * @param {Object} [logger] a configured logger object, optionally `console`, which can used to display debug and warning messages.
   */
  // eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
  constructor(settings: Settings, logger?: unknown);

  /**
   * @description Gets the user's profile data and returns it if it exists. Should be called after {@link userSessionExists} or it will be empty.
   * @return {Object} The user data object.
   */
  getUserData(): Record<string, unknown>;

  /**
   * @description Async wait for a user session to exist. Will block until {@link userSessionExists} or {@link authenticate} is called.
   * @return {Promise<void>}
   */
  waitForUserSession(): Promise<void>;

  /**
   * @description Call this function on every route change. It will check if the user just logged in or is still logged in.
   * @return {Promise<boolean>} Returns truthy if there a valid existing session, falsy otherwise.
   */
  userSessionExists(): Promise<boolean>;

  /**
   * @description Logs a user in, if the user is not logged in, will redirect the user to their selected connection/provider and then redirect back to the {@link redirectUrl}.
   * @param {AuthenticationParameters} settings Parameters for controlling how and when users should be authenticated for the app.
   * @return {Promise<boolean>} Is there a valid existing session.
   */
  authenticate(settings: AuthenticationParameters): Promise<boolean>;

  /**
   * @description Ensures the user's bearer token exists. To be used in the Authorization header as a Bearer token. This method blocks on a valid user session being created, and expects {@link authenticate} to have been called first. Additionally, if the application configuration specifies that tokens should be secured from javascript, the token will be a hidden cookie only visible to service APIs and will not be returned.
   * @return {Promise<string>} The Authorization Bearer token.
   */
  ensureToken(settings: TokenParameters): Promise<string>;

  /**
   * @description Log the user out removing the current user's session
   */
  logout(): Promise<void>;
}
