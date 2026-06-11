# identity-client

Client libraries for the shared `identity` auth service: the server-to-server
calls and the RS256 access-token verifier, packaged so consumers depend on one
canonical implementation instead of copy-pasting security-critical code.

Each language client lives in its own subdirectory:

- [`python/`](python/) — Python client + verifier (`identity-client` on PyPI-style
  git install). See [`python/README.md`](python/README.md).

Nothing secret lives in these clients: they only call identity and verify tokens
against its public JWKS key. The consumer supplies its own service credential at
runtime.
