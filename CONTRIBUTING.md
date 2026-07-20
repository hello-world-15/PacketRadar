# Contributing to PacketRadar

Thanks for your interest in PacketRadar. This is primarily a personal/portfolio
project, but issues, suggestions, and pull requests are welcome.

## Getting set up

Follow the [Getting Started](README.md#getting-started) section of the main
README to get the frontend and backend running locally.

## Before you start working on something

- **Bugs / small fixes** — feel free to open a pull request directly.
- **New features or larger changes** — please open an issue first to discuss
  the approach. This project follows a "one module at a time" philosophy
  (see `docs/contracts/`), and every feature has a written contract before
  implementation. Aligning on scope up front saves rework.

## Development guidelines

- **Data contracts first.** If you're adding or changing an API
  endpoint/WebSocket event, add or update the relevant file in
  `docs/contracts/` describing the payload shape and transport before
  writing the implementation.
- **Don't fake data.** If a field or feature isn't genuinely implemented,
  leave it out or mark it clearly as not-yet-implemented rather than
  hardcoding a placeholder value. See `backend/README.md`'s "What's real
  vs. stubbed" tables for the existing convention.
- **Pure functions where possible.** Backend `engines/` are written as pure,
  unit-testable functions/classes, kept separate from the FastAPI routing
  and Scapy capture layers. New engines should follow the same pattern.
- **Tests.** New backend logic should come with a corresponding test in
  `backend/tests/`. Run the suite with:
  ```bash
  cd backend
  pip install pytest httpx
  python -m pytest tests/ -v
  ```

## Reporting security issues

This project captures live network traffic — if you find a security issue
(e.g. something that could leak captured data, or a way to trigger capture
without consent), please open an issue and flag it clearly rather than
filing it as a routine bug.

## Code of conduct

Be respectful and constructive. Disagreements about implementation approach
are fine and expected; personal attacks are not.
