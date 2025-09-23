const cookieManager = require('cookie');
const windowManager = require('./windowManager');

const AuthenticationCredentialsStorageKey = 'AuthenticationCredentialsStorage';

const cookieKeys = {
  user: 'user',
  authorization: 'authorization',
  authCode: 'auth-code',
  authUserId: 'AuthUserId'
};

class UserIdentityTokenStorageManager {
  constructor() {
    this.retainUserCookie = false;
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
    // Skip empty cookies when fetching
    const authorizationTokens = document.cookie.split(';').filter(c => c.split('=')[0].trim() === cookieKeys.authorization).map(c => c.trim().replace(/^authorization=/, '')).filter(c => c && c.trim());
    return authorizationTokens;
  }

  set(value, expiry) {
    if (typeof window === 'undefined' || typeof document === 'undefined') {
      return;
    }

    try {
      const cookies = cookieManager.parse(document.cookie);
      localStorage.setItem(AuthenticationCredentialsStorageKey, JSON.stringify({ idToken: value, expiry: expiry && expiry.getTime(), jsCookies: !!cookies.authorization }));
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

    let cookies = {};
    try {
      cookies = cookieManager.parse(document.cookie);
    } catch (error) {
      console.debug('CookieManagement failed in Browser', error);
    }

    try {
      const { idToken, expiry, jsCookies } = JSON.parse(localStorage.getItem(AuthenticationCredentialsStorageKey) || '{}');
      if (!idToken) {
        return this.getUserCookie();
      }

      if (expiry < Date.now()) {
        return null;
      }

      // If the authorization cookie was present when the identity was stored, then it must still be present after, otherwise we know that the user data saved isn't valid anymore
      // * If the authorization cookie wasn't present, then it is because the application configuration restricts access to javascript.
      // * That means that the implementation can't use the presence of the ID token information to make a decision about if the user is logged in.
      if (jsCookies && !cookies.authorization) {
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
        const cookieBase = `${encodeURIComponent(cookie.split(';')[0].split('=')[0])}=; expires=Thu, 01-Jan-1970 00:00:01 GMT; ${domainString} SameSite=Strict; path=`;
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

module.exports = new UserIdentityTokenStorageManager();
