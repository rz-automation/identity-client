/**
 * identity-auth: the shared front-end for identity login buttons.
 *
 * One dependency-free ES module that renders the enabled provider buttons and
 * runs each provider's browser flow, so every consumer stops copy-pasting the
 * GIS-button + fetch + Discord-redirect glue. It is framework-agnostic (plain
 * DOM) and backend-agnostic: it talks ONLY to the consumer's own same-origin
 * auth routes (the endpoints `identity_client.fastapi.auth_router` mounts, or
 * any backend that implements the same contract), never to identity directly.
 * That is deliberate — identity's auth endpoints emit no CORS and the service
 * credential lives in the consumer backend, so the browser must go through it.
 *
 * Contract it expects at `basePath` (default "/api/auth"):
 *   GET  {basePath}/auth-config   -> { providers: [
 *                                        { id: "google", client_id: "..." },
 *                                        { id: "discord", start_url: "..." } ] }
 *   POST {basePath}/login         <- { provider: "google", credential }  (Google)
 *   GET  {basePath}/discord/callback   (browser is redirected here by identity)
 *   GET  {basePath}/session       -> { authenticated: bool }
 *   POST {basePath}/logout
 *
 * Google runs in-page (Google Identity Services popup) and POSTs the credential
 * to /login. Discord is a top-level navigation to identity's start URL; identity
 * runs the OAuth dance and redirects the browser back through the consumer's
 * /discord/callback, which establishes the session and lands on the app — so the
 * Discord button is just a link, no JS exchange in the browser.
 *
 * No secrets and no PII live here: only public client ids and public URLs.
 */

const GIS_SRC = "https://accounts.google.com/gsi/client";

const DEFAULT_LABELS = {
  discord: "Continue with Discord",
  error: "Sign-in failed. Please try again.",
};

let _gisPromise = null;

/** Load the Google Identity Services script once; resolve when ready. */
function loadGoogleIdentityServices() {
  if (_gisPromise) return _gisPromise;
  _gisPromise = new Promise((resolve, reject) => {
    if (window.google && window.google.accounts && window.google.accounts.id) {
      resolve();
      return;
    }
    const existing = document.querySelector(`script[src="${GIS_SRC}"]`);
    const script = existing || document.createElement("script");
    script.addEventListener("load", () => resolve());
    script.addEventListener("error", () => reject(new Error("failed to load GIS")));
    if (!existing) {
      script.src = GIS_SRC;
      script.async = true;
      document.head.appendChild(script);
    }
  });
  return _gisPromise;
}

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else node.setAttribute(k, v);
  }
  for (const child of children) node.appendChild(child);
  return node;
}

/**
 * Render login buttons for every enabled provider into `container`.
 *
 * @param {HTMLElement|string} container  element or selector to render into
 * @param {object} [options]
 * @param {string} [options.basePath="/api/auth"]  where the consumer mounted auth_router
 * @param {(result: object) => void} [options.onSignedIn]  called after a successful Google sign-in
 * @param {(message: string) => void} [options.onError]  called on any sign-in failure
 * @param {object} [options.googleButton]  options forwarded to GIS renderButton
 * @param {object} [options.labels]  text overrides ({ discord, error })
 * @returns {Promise<{ providers: string[] }>}  the provider ids that were rendered
 */
export async function mountAuth(container, options = {}) {
  const root =
    typeof container === "string" ? document.querySelector(container) : container;
  if (!root) throw new Error("identity-auth: container not found");

  const basePath = (options.basePath || "/api/auth").replace(/\/$/, "");
  const labels = { ...DEFAULT_LABELS, ...(options.labels || {}) };
  const onSignedIn =
    options.onSignedIn || (() => window.location.assign("/"));
  const onError =
    options.onError ||
    ((msg) => {
      // Best-effort visible error; consumers usually pass their own.
      console.error("identity-auth:", msg);
    });

  // Surface a Discord-callback failure that landed back here as ?error=...
  const params = new URLSearchParams(window.location.search);
  if (params.has("error")) onError(labels.error);

  let config;
  try {
    const resp = await fetch(`${basePath}/auth-config`, {
      credentials: "same-origin",
    });
    if (!resp.ok) throw new Error(`auth-config ${resp.status}`);
    config = await resp.json();
  } catch (e) {
    onError(labels.error);
    throw e;
  }

  root.replaceChildren();
  const rendered = [];

  for (const provider of config.providers || []) {
    if (provider.id === "google" && provider.client_id) {
      const slot = el("div", { class: "identity-auth-google" });
      root.appendChild(slot);
      await renderGoogle(slot, provider.client_id, {
        basePath,
        onSignedIn,
        onError,
        labels,
        buttonOptions: options.googleButton || {},
      });
      rendered.push("google");
    } else if (provider.id === "discord" && provider.start_url) {
      root.appendChild(renderDiscord(provider.start_url, labels));
      rendered.push("discord");
    }
  }

  return { providers: rendered };
}

async function renderGoogle(slot, clientId, ctx) {
  const { basePath, onSignedIn, onError, labels, buttonOptions } = ctx;
  try {
    await loadGoogleIdentityServices();
  } catch (e) {
    onError(labels.error);
    return;
  }
  window.google.accounts.id.initialize({
    client_id: clientId,
    callback: async (response) => {
      try {
        const resp = await fetch(`${basePath}/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
          body: JSON.stringify({
            provider: "google",
            credential: response.credential,
          }),
        });
        if (resp.ok) {
          onSignedIn(await safeJson(resp));
          return;
        }
        onError((await safeJson(resp))?.error || labels.error);
      } catch (e) {
        onError(labels.error);
      }
    },
  });
  window.google.accounts.id.renderButton(slot, {
    theme: "outline",
    size: "large",
    text: "signin_with",
    width: 320,
    ...buttonOptions,
  });
}

function renderDiscord(startUrl, labels) {
  // A plain top-level navigation: identity owns the whole OAuth dance and
  // redirects the browser back through the consumer's /discord/callback.
  const link = el("a", {
    class: "identity-auth-discord",
    href: startUrl,
    role: "button",
    text: labels.discord,
  });
  return link;
}

async function safeJson(resp) {
  try {
    return await resp.json();
  } catch {
    return null;
  }
}

/** Report whether the current browser has a live session. */
export async function getSession(basePath = "/api/auth") {
  try {
    const resp = await fetch(`${basePath.replace(/\/$/, "")}/session`, {
      credentials: "same-origin",
    });
    if (!resp.ok) return false;
    const data = await resp.json();
    return Boolean(data && data.authenticated);
  } catch {
    return false;
  }
}

/** Revoke + clear the session, then run `after` (defaults to reloading). */
export async function logout(basePath = "/api/auth", after) {
  try {
    await fetch(`${basePath.replace(/\/$/, "")}/logout`, {
      method: "POST",
      credentials: "same-origin",
    });
  } catch {
    // logout must always be able to tear the local session down.
  }
  (after || (() => window.location.assign("/")))();
}

export default { mountAuth, getSession, logout };
