import { vi } from 'vitest';

/**
 * Splits a written cookie string into its parts so that assertions do not depend on the attribute order the cookie library chooses, browsers ignore that order.
 */
export function parseCookieWrite(cookieWrite) {
  const [nameValuePair, ...attributePairs] = cookieWrite.split(';').map(part => part.trim());
  const separatorIndex = nameValuePair.indexOf('=');
  const attributes = Object.fromEntries(attributePairs.map(attributePair => {
    const [attributeName, ...attributeValue] = attributePair.split('=');
    return [attributeName.toLowerCase(), attributeValue.length ? attributeValue.join('=') : true];
  }));
  return { name: nameValuePair.slice(0, separatorIndex), value: nameValuePair.slice(separatorIndex + 1), attributes };
}

/**
 * Stands in for the browser's `document.cookie`, keeping every raw write for attribute assertions and exposing the surviving cookies the way a browser reads them back.
 * Path and domain scoping are not modelled, since the SDK only reads cookies from the page it wrote them on.
 */
export function stubBrowserCookieJar(locationUrl) {
  const cookieJar = new Map();
  const cookieWrites = [];
  const fakeDocument = {};
  Object.defineProperty(fakeDocument, 'cookie', {
    set(cookieWrite) {
      cookieWrites.push(cookieWrite);
      const { name, value, attributes } = parseCookieWrite(cookieWrite);
      if (attributes.expires && Date.parse(attributes.expires) <= Date.now()) {
        cookieJar.delete(name);
        return;
      }
      cookieJar.set(name, value);
    },
    get: () => [...cookieJar].map(([name, value]) => `${name}=${value}`).join('; ')
  });
  vi.stubGlobal('window', { location: new URL(locationUrl) });
  vi.stubGlobal('document', fakeDocument);
  return { cookieJar, cookieWrites };
}

export const findCookieWrite = (cookieWrites, cookieName) => cookieWrites.map(parseCookieWrite).find(cookieWrite => cookieWrite.name === cookieName);
