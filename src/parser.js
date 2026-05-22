'use strict';

function parseHAR(raw) {
  if (!raw || !raw.log) throw new Error('Invalid HAR: missing "log" property');
  if (!Array.isArray(raw.log.entries)) throw new Error('Invalid HAR: missing "log.entries" array');

  const entries = raw.log.entries.map(e => {
    const reqHeaders  = headersToMap(e.request?.headers  || []);
    const resHeaders  = headersToMap(e.response?.headers || []);

    const contentType = resHeaders['content-type'] || '';
    const isTextBody  = /text\/|application\/(json|xml|javascript|xhtml)/.test(contentType);
    const bodyText    = isTextBody ? (e.response?.content?.text || '') : '';

    return {
      request: {
        url:         e.request?.url         || '',
        method:      e.request?.method      || '',
        headers:     e.request?.headers     || [],
        headerMap:   reqHeaders,
        queryString: e.request?.queryString || [],
        cookies:     e.request?.cookies     || [],
        postData:    e.request?.postData?.text || '',
      },
      response: {
        status:      e.response?.status     || 0,
        headers:     e.response?.headers    || [],
        headerMap:   resHeaders,
        cookies:     e.response?.cookies    || [],
        bodyText,
        contentType,
      },
    };
  });

  const pages     = raw.log.pages || [];
  const createdAt = raw.log.pages?.[0]?.startedDateTime || new Date().toISOString();

  return {
    entries,
    meta: {
      entryCount: entries.length,
      pageCount:  pages.length,
      createdAt,
      version:    raw.log.version || '',
      creator:    raw.log.creator?.name || '',
    },
  };
}

function headersToMap(headers) {
  const map = {};
  for (const h of headers) {
    map[h.name.toLowerCase()] = h.value;
  }
  return map;
}

module.exports = { parseHAR };
