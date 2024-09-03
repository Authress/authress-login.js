const { sanitizeUrl } = require('./util');
const windowManager = require('./windowManager');
const packageInfo = require('../package.json');

const defaultHeaders = {
  'Content-Type': 'application/json',
  'X-Powered-By': `Authress Login SDK; Javascript; ${packageInfo.version}`
};

const errorMessages = new Set([
  'Failed to fetch', // Chrome
  'NetworkError when attempting to fetch resource.', // Firefox
  'The Internet connection appears to be offline.', // Safari 16
  'Network request failed', // `cross-fetch`
  'fetch failed', // Undici (Node.js)
  'Load failed', // iOS Fetch failed to respond - https://stackoverflow.com/questions/71280168/javascript-typeerror-load-failed-error-when-calling-fetch-on-ios
  '<HTML DOCUMENT></HTML>' // Handle some HTML error page responses as well, or sometimes CDN is having problems, if the response includes an HTML Document, then for sure there was an issue
]);

function isNetworkError(error) {
  return error && error.message && typeof error.message === 'string' && errorMessages.has(error.message)
    || error && error.data && typeof error.data === 'string' && errorMessages.has(error.data);
}

async function retryExecutor(func) {
  let lastError = null;
  for (let iteration = 0; iteration < 5; iteration++) {
    try {
      const result = await func();
      return result;
    } catch (error) {
      error.retryCount = iteration;
      lastError = error;
      if (isNetworkError(error) || error.message === 'Network Error' || error.code === 'ERR_NETWORK' || !error.status || error.status >= 500) {
        lastError.isNetworkError = true;
        await new Promise(resolve => setTimeout(resolve, 10 * 2 ** iteration));
        continue;
      }
      throw error;
    }
  }
  throw lastError;
}

class HttpClient {
  constructor(authressLoginCustomDomain, overrideLogger) {
    if (!authressLoginCustomDomain) {
      throw Error('Custom Authress Domain Host is required');
    }
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    const logger = overrideLogger || { debug() {}, warn() {}, critical() {} };
    this.logger = logger;

    const loginHostFullUrl = new URL(sanitizeUrl(authressLoginCustomDomain));
    this.loginUrl = `${loginHostFullUrl.origin}/api`;
  }

  get(url, withCredentials, headers, ignoreExpectedWarnings) {
    return retryExecutor(() => {
      return this.fetchWrapper('GET', url, null, headers, withCredentials, ignoreExpectedWarnings);
    });
  }

  delete(url, withCredentials, headers, ignoreExpectedWarnings) {
    return retryExecutor(() => {
      return this.fetchWrapper('DELETE', url, null, headers, withCredentials, ignoreExpectedWarnings);
    });
  }

  post(url, withCredentials, data, headers, ignoreExpectedWarnings) {
    return retryExecutor(() => {
      return this.fetchWrapper('POST', url, data, headers, withCredentials, ignoreExpectedWarnings);
    });
  }

  put(url, withCredentials, data, headers, ignoreExpectedWarnings) {
    return retryExecutor(() => {
      return this.fetchWrapper('PUT', url, data, headers, withCredentials, ignoreExpectedWarnings);
    });
  }

  patch(url, withCredentials, data, headers, ignoreExpectedWarnings) {
    return retryExecutor(() => {
      return this.fetchWrapper('PATCH', url, data, headers, withCredentials, ignoreExpectedWarnings);
    });
  }

  async fetchWrapper(rawMethod, urlObject, data, requestHeaders, withCredentials, ignoreExpectedWarnings) {
    const url = `${this.loginUrl}${urlObject.toString()}`;
    const method = rawMethod.toUpperCase();
    const headers = Object.assign({}, defaultHeaders, requestHeaders);
    try {
      this.logger && this.logger.debug && this.logger.debug({ title: 'HttpClient Request', method, url });
      const request = { method, headers };
      if (data) {
        request.body = JSON.stringify(data);
      }
      if (!windowManager.isLocalHost() && !!withCredentials) {
        request.credentials = 'include';
      }
      const response = await fetch(url, request);

      if (!response.ok) {
        throw response;
      }

      let responseBody = {};
      try {
        responseBody = await response.text();
        responseBody = JSON.parse(responseBody);
      } catch (error) {
        /* */
      }
      return {
        url,
        headers: response.headers,
        status: response.status,
        data: responseBody
      };
    } catch (error) {
      let resolvedError = error;
      try {
        resolvedError = await error.text();
        resolvedError = JSON.parse(resolvedError);
      } catch (parseError) {
        /* */
      }

      const extensionErrorId = resolvedError.stack && resolvedError.stack.match(/chrome-extension:[/][/](\w+)[/]/);
      if (extensionErrorId) {
        this.logger && this.logger.debug && this.logger.debug({ title: `Fetch failed due to a browser extension - ${method} - ${url}`, method, url, data, headers, error, resolvedError, extensionErrorId });
        const newError = new Error(`Extension Error ID: ${extensionErrorId}`);
        newError.code = 'BROWSER_EXTENSION_ERROR';
        throw newError;
      }

      const status = error.status;
      let level = 'warn';
      let message = 'HttpClient Response Error';
      if (!error) {
        message = 'HttpClient Response Error - Unknown error occurred';
      } else if (status === 401) {
        message = 'HttpClient Response Error due to invalid token';
        level = 'debug';
      } else if (status === 404) {
        message = 'HttpClient Response: Not Found';
        level = 'debug';
      } else if (status < 500 && ignoreExpectedWarnings) {
        level = 'debug';
      }

      if (this.logger && this.logger[level]) {
        this.logger[level]({
          title: message,
          online: typeof navigator === 'undefined' || navigator.onLine,
          method, url, status, data, headers, error, resolvedError
        });
      }

      const httpError = {
        url: url,
        status: status,
        data: resolvedError,
        headers: error.headers
      };
      throw httpError;
    }
  }
}

module.exports = HttpClient;
