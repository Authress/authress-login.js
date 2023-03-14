# Change log
This is the changelog for [Authress Login](readme.md).

## 2.1 ##
* Remove `connectionId` and `tenantLookupIdentifier` requirements from the authentication call so that the user can be directed to the Authress Hosted login when necessary: https://authress.io/app/#/settings?focus=branding
* Enable the methods to have optional inputs parameters when not required

## 2.0 ##
* Optimize cookie storage location for the `user` cookie.
* Use more secure `PATCH` for session management.
* Remove deprecated properties from previous version.
* Increase time span for duplicate session checks to 50ms
* Add automatic retries to network connection issues.
* Add AuthUserId cookie available in all requests to replace the `user` cookie.
* Avoid unnecessary CORS warnings when using a cross domain application
* Improve logout redirect url default location

## 1.4 ##
* Include the extensionClient as embeddable client for OAuth extension login.
* Add `linkIdentity` parameter to Authenticate and `unlinkIdentity` method to support account linking.

## 1.3 ##
* Automatically trigger credentials checking on load.
* Support 127.0.0.1 for localhost
* Add the `updateExtensionAuthenticationRequest` method to support handling platform extension login.

## 1.2 ##
* Use builtin `crypto.subtle` for all crypto operations.
* Publish a babel to work with vanilla.js.

## 1.1 ##
* Added `authorization-code` exchange specifying necessary parameters `responseMode = query` and `responseType = code`.
* Calling `authenticate` no longer redirects user to the `redirectUrl` if the user is already logged in. Redirects will still happen for users not logged in. This fixes a problem where the mechanism for redirects did not match the framework redirect mechanism. In some cases causing refresh loops.
* Return the full OIDC identity when calling `getUserData()` instead of only a limited set.
* Add `tenantLookupIdentifier` property to `authenticate` to specify a specific tenant to use rather than just the `connection`.
* Support `connectionProperties` in `authenticate` to override connection and identity provider specific defaults.
* `logout` redirects the user client to the hosted login UI to ensure logout happens, and then is redirected back.
* Add `UserCredentials` and `getConnectionCredentials` to fetch the credentials associated with the connected provider.
* Deprecate `getUserData` in favor of `getUserIdentity`
