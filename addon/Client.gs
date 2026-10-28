/**
 * Talks to the backend. Requests are signed with HMAC-SHA256 over
 * "<timestamp>.<body>", and the response is validated before use,
 * because the backend's answer is also treated as untrusted input.
 */
function analyzeEmail(payload) {
  const props = PropertiesService.getScriptProperties();
  const baseUrl = props.getProperty('BACKEND_URL');
  const secret = props.getProperty('HMAC_SECRET');
  if (!baseUrl || !secret) throw new Error('Add-on is not configured');

  const body = JSON.stringify(payload);
  const timestamp = String(Math.floor(Date.now() / 1000));
  const signature = toHex(Utilities.computeHmacSha256Signature(
    timestamp + '.' + body, secret, Utilities.Charset.UTF_8));

  const response = UrlFetchApp.fetch(baseUrl.replace(/\/$/, '') + '/analyze', {
    method: 'post',
    contentType: 'application/json; charset=utf-8',
    payload: body,
    headers: { 'X-Timestamp': timestamp, 'X-Signature': signature },
    muteHttpExceptions: true,
  });
  if (response.getResponseCode() !== 200) {
    throw new Error('Backend returned HTTP ' + response.getResponseCode());
  }
  return validateResult(JSON.parse(response.getContentText()));
}

function validateResult(r) {
  if (!r || typeof r.score !== 'number' || r.score < 0 || r.score > 100 ||
      !Object.prototype.hasOwnProperty.call(VERDICT_LABELS, r.verdict) ||
      !Array.isArray(r.signals)) {
    throw new Error('Unexpected response from backend');
  }
  return {
    score: Math.round(r.score),
    verdict: r.verdict,
    summary: String(r.summary || '').slice(0, 500),
    signals: r.signals.slice(0, 30).map(function (s) {
      return {
        category: String(s.category || '').slice(0, 50),
        description: String(s.description || '').slice(0, 500),
        points: Math.max(0, Math.round(Number(s.points) || 0)),
      };
    }),
  };
}

function toHex(bytes) {
  return bytes.map(function (b) {
    return ('0' + (b & 0xff).toString(16)).slice(-2);
  }).join('');
}
