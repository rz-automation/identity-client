# identity-auth (web)

The shared front-end for identity login buttons. One dependency-free ES module
that renders the enabled provider buttons (Google, Discord) and runs each
provider's browser flow, so consumers stop copy-pasting the GIS-button + fetch +
Discord-redirect glue into every app.

It is framework-agnostic (plain DOM) and backend-agnostic: it talks **only** to
your own same-origin auth routes — the endpoints
`identity_client.fastapi.auth_router` mounts, or any backend that implements the
same contract. It never calls identity directly (identity's auth endpoints emit
no CORS and the service credential lives in your backend), so the browser always
goes through your server.

No secrets and no PII live in this module: only public client ids and public URLs.

## Use it

```html
<div id="login"></div>
<link rel="stylesheet" href="/path/to/identity-auth.css" />  <!-- optional -->
<script type="module">
  import { mountAuth } from "/path/to/identity-auth.js";

  await mountAuth("#login", {
    basePath: "/api/auth",                 // where you mounted auth_router
    onSignedIn: () => location.assign("/"),
    onError: (msg) => showBanner(msg),
  });
</script>
```

That renders whatever providers your backend advertises. Add or remove a provider
in identity's admin console and the buttons follow — no front-end change.

### What each provider does

- **Google** runs in-page via Google Identity Services (popup) and POSTs the
  credential to `{basePath}/login`. `onSignedIn` fires on success.
- **Discord** is a top-level navigation to identity's start URL. identity runs
  the OAuth dance and redirects the browser back through
  `{basePath}/discord/callback`, which establishes the session and lands on your
  app. So the Discord button is just a link; there is no JS exchange in the
  browser, and `onSignedIn` is not used for it (the redirect is the success).
  A Discord failure comes back as `?error=...` on your post-login page, which
  `mountAuth` surfaces through `onError` on its next mount.
- **Password** (email + password) renders a small in-page form — email and
  password inputs, a primary button, and a "Create account" toggle that flips
  the action between login and signup. On submit it POSTs `{ email, password }`
  same-origin to `{basePath}/password/login` or `{basePath}/password/signup`;
  `onSignedIn` fires on success, and the server's `{ error }` message is shown
  via `onError` on failure.

### Helpers

```js
import { getSession, logout } from "/path/to/identity-auth.js";

if (await getSession("/api/auth")) { /* already signed in */ }
await logout("/api/auth");          // revoke + clear, then redirect
```

## Backend wiring

Register your Discord return URL in identity's admin console as the service's
Discord return URL, pointing at this module's callback route, e.g.
`https://app.example.com/api/auth/discord/callback`. With the Python client that
route is provided for free by `auth_router`; set where it lands with
`auth_router(sessions, post_login_path="/")`.
