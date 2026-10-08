# Security Policy

## Status

This is a research and demonstration project. It is not independently audited and is
not intended for production use. The engine binds to `localhost` only and never
listens on external interfaces.

## Reporting a Vulnerability

Open a GitHub issue in this repository. If an issue could put users at risk, keep the
description minimal (no working exploit) and mark it clearly so it can be handled
before details are made public.

## Security-Relevant Behavior

- **Keys:** test signing keys are generated once into the ignored `keys/` directory.
  Never commit real key material (`*.pkcs8`, `*.x509`, `*.key`).
- **Chain config:** `config/chain.json` can contain a `privateKey`, written only for
  chain id 31337 (the local development chain) and only when the derived address
  matches the deploying account. Never place a real, funded key in this file.
- **Baseline:** `config/baseline.json` is the measured golden state that the verifier
  checks against. Review any change to it before committing.
- **Fail-closed:** missing files, bad signatures, sequence gaps, and baseline
  mismatches produce `POLICY_MISMATCH` verdicts, not a pass.
- **Dependencies:** the runtime is pure JDK (no third-party libraries) and the
  Solidity contract is compiled with a fixed, pinned compiler. CI verifies the
  committed build artifacts and hashes.
