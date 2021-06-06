/* eslint-disable @typescript-eslint/explicit-module-boundary-types */
const axios = require('axios');

const defaultHeaders = {
  'Content-Type': 'application/json'
};

class HttpClient {
  constructor(authressLoginCustomDomain, overrideLogger) {
    if (!authressLoginCustomDomain) {
      throw Error('Custom Authress Domain Host is required');
    }
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    const logger = overrideLogger || { debug() {}, warn() {}, critical() {} };

    const loginHostFullUrl = new URL(`https://${authressLoginCustomDomain.replace(/^(https?:\/+)/, '')}`);
    const loginUrl = `${loginHostFullUrl.origin}/api`;
    const client = axios.create({ baseURL: loginUrl });

    client.interceptors.request.use(config => {
      logger.debug({ title: 'HttpClient Request', online: navigator.onLine, requestId: config.requestId, method: config.method, url: config.url });

      return config;
    }, error => {
      let notFound = false;
      let newError = error;
      let url;
      let requestId;

      if (error) {
        newError = error.message;

        if (error.response) {
          newError = {
            data: error.response.data,
            status: error.response.status,
            headers: error.response.headers
          };
          notFound = error.response.status === 404;
        } else if (error.message) {
          newError = {
            message: error.message,
            code: error.code,
            stack: error.stack
          };
        }

        if (error.config) {
          url = error.config.url;
          requestId = error.config.requestId;
        } else {
          requestId = error.request && error.request.config && error.request.config.requestId;
        }
      }

      const logObject = { title: 'HttpClient Request Error', url, online: navigator.onLine, requestId, exception: newError };

      if (notFound) {
        logger.debug(logObject);
      } else {
        logger.warn(logObject);
      }

      throw newError;
    });

    client.interceptors.response.use(response => response, error => {
      // Rewritten error object for easy consumption
      if (error.re) {
        throw error;
      }

      const newError = error && error.response && {
        url: error.config && error.config.url,
        data: error.response.data,
        status: error.response.status,
        headers: error.response.headers
      } || error.message && { message: error.message, code: error.code, stack: error.stack } || error;
      newError.re = true;
      const requestId = error && (error.config && error.config.requestId || error.request && error.request.config && error.request.config.requestId);

      let message = 'HttpClient Response Error';
      let logMethod = 'warn';

      if (!error) {
        message = 'HttpClient Response Error - Unknown error occurred';
      } else if (error.response && error.response.status === 404) {
        logMethod = 'debug';
      } else if (error.response && error.response.status === 401) {
        message = 'HttpClient Response Error due to invalid token';
      }

      logger[logMethod]({ title: message, online: navigator.onLine, requestId, exception: newError, url: error && error.config && error.config.url });
      throw newError;
    });

    this.client = client;
  }

  get(url, withCredentials, headers, type = 'json') {
    return this.client.get(url.toString(), {
      withCredentials: window.location.hostname !== 'localhost' && !!withCredentials,
      headers: Object.assign({}, defaultHeaders, headers),
      responseType: type
    });
  }

  delete(url, withCredentials, headers, type = 'json') {
    return this.client.delete(url.toString(), {
      withCredentials: window.location.hostname !== 'localhost' && !!withCredentials,
      headers: Object.assign({}, defaultHeaders, headers),
      responseType: type
    });
  }

  post(url, withCredentials, data, headers) {
    return this.client.post(url.toString(), data, {
      withCredentials: window.location.hostname !== 'localhost' && !!withCredentials,
      headers: Object.assign({}, defaultHeaders, headers)
    });
  }

  put(url, withCredentials, data, headers) {
    return this.client.put(url.toString(), data, {
      withCredentials: window.location.hostname !== 'localhost' && !!withCredentials,
      headers: Object.assign({}, defaultHeaders, headers)
    });
  }

  patch(url, withCredentials, data, headers) {
    return this.client.patch(url.toString(), data, {
      withCredentials: window.location.hostname !== 'localhost' && !!withCredentials,
      headers: Object.assign({}, defaultHeaders, headers)
    });
  }
}

module.exports = HttpClient;
