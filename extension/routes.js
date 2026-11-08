// The sender rules of INT-11.11 and INT-11.12: who sent a runtime message,
// read from `runtime.MessageSender` alone, never from the message body. Pure:
// tested under macOS's jsc (INT-11.43, extension/test/pure_test.js).

// A serialized http or https URL (the browser's own form, INT-01.27): scheme,
// user info (not part of the origin), host and port, then the path's "/".
const WEB = /^(https?):\/\/(?:[^@/?#]*@)?([^@/?#]+)\//;

/** The origin of a serialized http or https URL, or null for any other URL. */
export function webOrigin(url) {
  const m = typeof url === 'string' ? WEB.exec(url) : null;
  return m ? `${m[1]}://${m[2]}` : null;
}

/**
 * Classes the sender of one runtime message for the routing table
 * (INT-11.12). `self` is this extension: {id, origin}, the origin being
 * "chrome-extension://‹id›" or the browser's own form.
 *
 * Returns {kind, url, origin, frameId, documentId, tabId, topUrl}, every
 * value taken from `sender`, with kind "C" (a content script: an http or
 * https page in a tab), "F" (an in-page frame: this extension's page under
 * frames/ in a subframe of a tab), or "P" (exactly the popup with no tab, or
 * exactly the options page as a top frame: `frameId` 0). Returns null
 * (the message is refused, INT-11.11) for a sender of another extension, an
 * opaque origin or one that is not its URL's origin, and any other URL.
 */
export function classify(sender, self) {
  if (!sender || sender.id !== self.id || typeof sender.url !== 'string') return null;
  const { url, origin, tab, frameId } = sender;
  const who = { url, origin, frameId, documentId: sender.documentId, tabId: tab?.id, topUrl: tab?.url };
  const web = webOrigin(url);
  if (web) return origin === web && tab ? { kind: 'C', ...who } : null;
  if (origin !== self.origin || !url.startsWith(`${self.origin}/`)) return null;
  const path = url.slice(self.origin.length);
  if (path.startsWith('/frames/') && tab && Number.isInteger(frameId) && frameId !== 0) return { kind: 'F', ...who };
  if (path === '/popup/popup.html' && !tab) return { kind: 'P', ...who };
  if (path === '/options/options.html' && frameId === 0) return { kind: 'P', ...who };
  return null;
}
