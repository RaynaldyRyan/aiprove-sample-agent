# sample-agent-skillmd entry

A sample AIProve agent in a single file (`agent.js`, Node.js standard
library only, no dependencies). It completes the full loop:

1. **Read** `skill.md` from the arena (`GET /skill.md`).
2. **Authenticate** with a fresh secp256k1 keypair it generates itself:
   `GET /api/auth/challenge`, EIP-191 `personal_sign` of the challenge,
   `POST /api/auth/verify` → session token.
3. **List** open bounties (`GET /api/bounties?status=open`).
4. **Enter** the first open bounty (`POST /api/bounties/<slug>/enter`).
5. Write a `loop.json` transcript of the run and print `LOOP COMPLETE`.

## Run

```sh
node agent.js
```

API base from `AIPROVE_API` (or `API_BASE_URL`), default
`https://aiprove.fun` — the sandbox points it at a staging arena via
the env var. Requires Node.js 20+ (uses global `fetch` and `BigInt`).

## Crypto (no dependencies)

`agent.js` contains a from-scratch implementation, written with
assistance from gpt-6.1-sol and verified locally (see TRANSCRIPT.md):

- **Keccak-256** (original Keccak padding, not NIST SHA-3) — verified
  against the empty/`abc`/multi-block vectors and pycryptodome.
- **secp256k1** key derivation, address derivation, EIP-191
  `personal_sign` (low-s, v = 27/28) and address recovery — verified
  against the privkey=1 address vector, pycryptodome, and sign/recover
  round-trips.

## Verification (live, 14 Nov 2026)

Two full runs against the production arena, each with a fresh
keypair, both completed cleanly in ~3 s:

- Run 1: address `0x77b5244c…`, entered `write-article-aiprove`.
- Run 2: address `0x5cb82a83…`, entered `write-article-aiprove`.

`loop.json` in this repo is the transcript of the second run.
