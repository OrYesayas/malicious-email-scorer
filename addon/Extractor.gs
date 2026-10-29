/**
 * Collects only the parts of the email the backend needs, with hard size limits.
 * Attachments are not read or sent at all.
 */
const LIMITS = {
  BODY_CHARS: 50000,
  HEADER_VALUE_CHARS: 2000,
  MAX_HEADERS: 50,
  MAX_LINKS: 100,
  LINK_CHARS: 2048,
  LINK_TEXT_CHARS: 300,
};

const WANTED_HEADERS = [
  'authentication-results', 'received-spf', 'from', 'reply-to', 'return-path', 'message-id',
];

/** Collects the details the server needs from the open email, each with a size limit. */
function extractEmail(message) {
  return {
    headers: parseHeaders(message.getRawContent()),
    sender: (message.getFrom() || '').slice(0, 500),
    reply_to: (message.getReplyTo() || '').slice(0, 500),
    subject: (message.getSubject() || '').slice(0, 1000),
    body_text: (message.getPlainBody() || '').slice(0, LIMITS.BODY_CHARS),
    links: extractLinks(message.getBody() || ''),
  };
}

/** Parses the raw header block, keeping the original top-to-bottom order. */
function parseHeaders(raw) {
  const end = raw.search(/\r?\n\r?\n/);
  const block = end === -1 ? raw : raw.slice(0, end);
  const unfolded = block.replace(/\r?\n[ \t]+/g, ' ');
  const headers = [];
  unfolded.split(/\r?\n/).forEach(function (line) {
    const colon = line.indexOf(':');
    if (colon <= 0 || headers.length >= LIMITS.MAX_HEADERS) return;
    const name = line.slice(0, colon).trim().toLowerCase();
    if (WANTED_HEADERS.indexOf(name) === -1) return;
    headers.push({
      name: name,
      value: line.slice(colon + 1).trim().slice(0, LIMITS.HEADER_VALUE_CHARS),
    });
  });
  return headers;
}

/**
 * Extracts <a href> links with their visible text.
 * Trade-off: a regex is not a full HTML parser, but email HTML is often
 * malformed, and a strict parser would reject it outright.
 */
function extractLinks(html) {
  const links = [];
  const re = /<a\b[^>]*?href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let m;
  while ((m = re.exec(html)) !== null && links.length < LIMITS.MAX_LINKS) {
    links.push({
      href: m[1].trim().slice(0, LIMITS.LINK_CHARS),
      text: stripTags(m[2]).slice(0, LIMITS.LINK_TEXT_CHARS),
    });
  }
  return links;
}

/** Removes HTML tags from a link's text, leaving only the words the user sees. */
function stripTags(s) {
  return s.replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim();
}
