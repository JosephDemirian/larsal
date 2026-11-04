// Answers every runtime message with what was asked and the sender's URL,
// so the driver's tests can see the service worker reply (story E7-S7b).
chrome.runtime.onMessage.addListener((message, sender, reply) => {
  reply({ answer: message, from: sender.url });
});
