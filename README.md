# identity-client

Clients for the shared `identity` auth service, packaged so consumers depend on
one canonical implementation instead of copy-pasting security-critical code.

The layout has two axes — **backend SDKs**, one per language, and a single shared
**web frontend** (there is only one because browsers run JS regardless of the
backend):

- [`python/`](python/) — Python backend SDK: the server-to-server calls, the
  RS256 access-token verifier, the framework-neutral session state machine
  (`SessionPolicy`), and an optional FastAPI integration. See
  [`python/README.md`](python/README.md). (Future backend languages, e.g.
  `kotlin/`, slot in here as siblings.)
- [`web/`](web/) — the browser login module (Google + Discord buttons and flows).
  Framework-agnostic, dependency-free, talks only to the consumer's own backend.
  See [`web/README.md`](web/README.md).

[`CONTRACT.md`](CONTRACT.md) is the language-neutral spec every client implements
against: the wire endpoints, the access-token verification invariants, the session
contract, and the provider flows. Write a new backend SDK (or a non-FastAPI
binding) from that document alone.

Nothing secret lives in these clients: they only call identity and verify tokens
against its public JWKS key. The consumer supplies its own service credential at
runtime, and the provider OAuth secrets never leave identity.
