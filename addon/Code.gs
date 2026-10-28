/**
 * Entry point: runs every time the user opens an email.
 */
function onGmailMessageOpen(e) {
  try {
    // Grants access to this one message only (least privilege).
    GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
    const message = GmailApp.getMessageById(e.gmail.messageId);

    const email = extractEmail(message);
    const result = analyzeEmail(email);
    return buildResultCard(result, splitSender(email.sender));
  } catch (err) {
    // Log only our own error message, never email content.
    console.error('Analysis failed: ' + err.message);
    return buildErrorCard();
  }
}
