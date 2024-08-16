module.exports.sanitizeUrl = function sanitizeUrl(rawUrlString) {
  let sanitizedUrl = rawUrlString;
  if (!sanitizedUrl.startsWith('http')) {
    sanitizedUrl = `https://${sanitizedUrl}`;
  }

  const url = new URL(sanitizedUrl);
  const domainBaseUrlMatch = url.host.match(/^([a-z0-9-]+)[.][a-z0-9-]+[.]authress[.]io$/);
  if (domainBaseUrlMatch) {
    url.host = `${domainBaseUrlMatch[1]}.login.authress.io`;
    sanitizedUrl = url.toString();
  }

  return sanitizedUrl.replace(/[/]+$/, '');
};
