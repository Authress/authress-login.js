import { stringifySetCookie } from 'cookie';
import windowManager from './windowManager.js';

const AuthenticationCredentialsStorageKey = 'AuthenticationCredentialsStorage';
const PersistedTokensStorageKey = 'AuthressPersistedTokens';

export const PersistenceType = Object.freeze({
  Cookie: 'COOKIE',
  LocalStorage: 'LOCAL_STORAGE'
});

const cookieKeys = {
  user: 'user',
  authorization: 'authorization',
  authressSession: 'authress-session',
  authCode: 'auth-code',
  authUserId: 'AuthUserId'
};

class UserIdentityTokenStorageManager {
  constructor() {
    this.retainUserCookie = false;
    this.persistenceType = PersistenceType.Cookie;
  }

  getUserCookie() {
    const document = windowManager.getDocument();
    if (!document) {
      return null;
    }

    // Skip empty cookies when fetching
    const val = document.cookie.split(';').filter(c => c.split('=')[0].trim() === cookieKeys.user).map(c => c.trim().replace(/^user=/, '')).find(c => c && c.trim()) || null;
    return val;
  }

  getAuthorizationTokens() {
    if (typeof window === 'undefined' || typeof document === 'undefined') {
      return [];
    }
    if (this.persistenceType === PersistenceType.LocalStorage) {
      const accessToken = this.getLocalStorageToken(cookieKeys.authorization);
      return accessToken ? [accessToken] : [];
    }
    // Skip empty cookies when fetching
    const authorizationTokens = document.cookie.split(';').filter(c => c.split('=')[0].trim() === cookieKeys.authorization).map(c => c.trim().replace(/^authorization=/, '')).filter(c => c && c.trim());
    return authorizationTokens;
  }

  setAuthorizationToken(accessToken, expiry) {
    this.persistToken(cookieKeys.authorization, accessToken, expiry);
  }

  setSessionToken(sessionToken, expiry) {
    this.persistToken(cookieKeys.authressSession, sessionToken, expiry);
  }

  persistToken(tokenName, value, expiry) {
    if (this.persistenceType === PersistenceType.LocalStorage) {
      this.setLocalStorageToken(tokenName, value, expiry);
      return;
    }
    this.setCookie(tokenName, value, expiry);
  }

  setCookie(cookieName, value, expiry) {
    const document = windowManager.getDocument();
    if (!document) {
      return;
    }
    document.cookie = stringifySetCookie({ name: cookieName, value: value || '', expires: expiry, path: '/', sameSite: 'strict', secure: windowManager.isHttps() });
  }

  getLocalStorageTokens() {
    try {
      return JSON.parse(localStorage.getItem(PersistedTokensStorageKey) || '{}');
    } catch (error) {
      console.debug('LocalStorage failed in Browser', error);
      return {};
    }
  }

  getLocalStorageToken(tokenName) {
    const { value, expiry } = this.getLocalStorageTokens()[tokenName] || {};
    if (!value || expiry && expiry < Date.now()) {
      return null;
    }
    return value;
  }

  clearLocalStorageTokens() {
    try {
      localStorage.removeItem(PersistedTokensStorageKey);
    } catch (error) {
      console.debug('LocalStorage failed in Browser', error);
    }
  }

  setLocalStorageToken(tokenName, value, expiry) {
    try {
      const tokens = this.getLocalStorageTokens();
      tokens[tokenName] = { value, expiry: expiry && expiry.getTime() };
      localStorage.setItem(PersistedTokensStorageKey, JSON.stringify(tokens));
    } catch (error) {
      console.debug('LocalStorage failed in Browser', error);
    }
  }

  set(value, expiry) {
    if (typeof window === 'undefined' || typeof document === 'undefined') {
      return;
    }

    try {
      const javascriptHadAccessToAuthorizationToken = this.getAuthorizationTokens().length > 0;
      localStorage.setItem(AuthenticationCredentialsStorageKey, JSON.stringify({ idToken: value, expiry: expiry && expiry.getTime(), jsCookies: javascriptHadAccessToAuthorizationToken }));
      if (!this.retainUserCookie) {
        this.clearCookies(cookieKeys.user);
      }
    } catch (error) {
      console.debug('LocalStorage failed in Browser', error);
    }
  }

  get() {
    if (typeof window === 'undefined' || typeof document === 'undefined') {
      return null;
    }

    try {
      const { idToken, expiry, jsCookies: javascriptHadAccessToAuthorizationToken } = JSON.parse(localStorage.getItem(AuthenticationCredentialsStorageKey) || '{}');
      if (!idToken) {
        return this.getUserCookie();
      }

      if (expiry < Date.now()) {
        return null;
      }

      // If the authorization cookie was present when the identity was stored, then it must still be present after, otherwise we know that the user data saved isn't valid anymore
      // * If the authorization cookie wasn't present, then it is because the application configuration restricts access to javascript.
      // * That means that the implementation can't use the presence of the ID token information to make a decision about if the user is logged in.
      if (javascriptHadAccessToAuthorizationToken && !this.getAuthorizationTokens().length) {
        return null;
      }

      return idToken;
    } catch (error) {
      console.debug('LocalStorage failed in Browser', error);
      return this.getUserCookie();
    }
  }

  delete() {
    try {
      localStorage.removeItem(AuthenticationCredentialsStorageKey);
    } catch (error) {
      console.debug('LocalStorage failed in Browser', error);
    }

    try {
      this.clearCookies(cookieKeys.user);
    } catch (error) {
      console.debug('CookieManagement failed in Browser', error);
    }
  }

  clear() {
    this.clearCookies();
    this.clearLocalStorageTokens();
    this.delete();
  }

  clearCookies(cookieName) {
    if (typeof window === 'undefined' || typeof document === 'undefined') {
      return;
    }

    const cookies = document.cookie.split('; ');
    for (const cookie of cookies) {
      // Remove only the cookies that are relevant to the client
      if (!Object.values(cookieKeys).includes(cookie.split('=')[0]) || cookieName && cookie.split('=')[0] !== cookieName) {
        continue;
      }

      const domainParts = window.location.hostname.split('.');

      const domainsToRemove = [...Array(domainParts.length - 1)].map((_, partLength) => domainParts.reverse().slice(0, partLength + 2).reverse().join('.')).map(domain => [domain, `.${domain}`]).flat(1).concat(null);

      if (window.location.hostname === 'localhost') {
        domainsToRemove.push('localhost');
      }

      // We will also clear cookies associated with localhost, but of course we don't need to clear domain cookies for the TLD, because parts like .com don't have cookies.
      // * So instead we loop on domain parts more than just a single part.
      for (const domain of domainsToRemove) {
        const domainString = domain ? `domain=${domain};` : '';
        const secureString = windowManager.isHttps() ? ' Secure;' : '';
        const cookieBase = `${encodeURIComponent(cookie.split(';')[0].split('=')[0])}=; expires=Thu, 01-Jan-1970 00:00:01 GMT; ${domainString} SameSite=Strict;${secureString} path=`;
        // console.log('clearing cookie', `${cookieBase}/`);
        document.cookie = `${cookieBase}/`;

        // Also update all the paths as well
        const path = location.pathname.split('/');
        while (path.length > 0) {
          // console.log('clearing cookie', cookieBase + path.join('/'));
          document.cookie = cookieBase + path.join('/');
          path.pop();
        }
      }
    }
  }
}

export default new UserIdentityTokenStorageManager();
