/**
 * Builds the UI. Card text supports basic HTML, and much of what is shown
 * comes from the email or the backend, so everything is escaped.
 */
const VERDICT_LABELS = {
  SAFE: '✅ Looks safe',
  SUSPICIOUS: '⚠️ Suspicious',
  MALICIOUS: '🛑 Likely malicious',
};

function buildResultCard(result, sender) {
  const header = CardService.newCardHeader()
    .setTitle(VERDICT_LABELS[result.verdict])
    .setSubtitle('Risk score: ' + result.score + ' / 100');

  const summary = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText(escapeHtml(result.summary)));

  const senderSection = CardService.newCardSection()
    .setHeader('Sender')
    .addWidget(CardService.newDecoratedText()
      .setTopLabel('Display name (chosen by the sender)')
      .setText(escapeHtml(sender.name || '(none)'))
      .setWrapText(true))
    .addWidget(CardService.newDecoratedText()
      .setTopLabel('Actual address')
      .setText(escapeHtml(sender.address))
      .setWrapText(true));

  const reasons = CardService.newCardSection().setHeader('Why this verdict');
  if (result.signals.length === 0) {
    reasons.addWidget(CardService.newTextParagraph().setText('No suspicious signals were found.'));
  }
  result.signals.forEach(function (s) {
    reasons.addWidget(CardService.newDecoratedText()
      .setTopLabel(escapeHtml(s.category) + ' · +' + s.points)
      .setText(escapeHtml(s.description))
      .setWrapText(true));
  });

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(summary)
    .addSection(senderSection)
    .addSection(reasons)
    .build();
}

function buildErrorCard() {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Could not analyze this email'))
    .addSection(CardService.newCardSection().addWidget(
      CardService.newTextParagraph().setText('Something went wrong. Please try again in a moment.')))
    .build();
}

// Splits 'Name <address@domain>' into its two parts.
// If there is no name, the whole text is treated as the address.
function splitSender(from) {
  const match = String(from).match(/^(.*?)\s*<([^>]+)>\s*$/);
  if (!match) {
    return { name: '', address: String(from).trim() };
  }
  return {
    name: match[1].replace(/^"|"$/g, '').trim(),
    address: match[2].trim(),
  };
}

// Turns text into plain text, so the card shows it
// instead of treating it as formatting commands.
function escapeHtml(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
