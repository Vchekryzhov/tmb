# Domain Docs

How the engineering skills consume this repo's domain documentation when exploring the codebase.

## Before exploring, read these

- `CONTEXT.md` at the repo root: the glossary.
- `docs/adr/`: read the ADRs that touch the area you're about to work in.

This is a single-context repo: one `CONTEXT.md`, one `docs/adr/`, no `CONTEXT-MAP.md`. If a file is missing, proceed silently; `/domain-modeling` creates it when a term or decision actually gets resolved.

## Use the glossary's vocabulary

When your output names a domain concept (in an issue title, a refactor proposal, a hypothesis, a test name), use the term as defined in `CONTEXT.md`. Don't drift to synonyms the glossary lists under `_Avoid_`.

If the concept you need isn't in the glossary yet, that's a signal: either you're inventing language the project doesn't use (reconsider) or there's a real gap (note it for `/domain-modeling`).

## Flag ADR conflicts

If your output contradicts an existing ADR, surface it explicitly rather than silently overriding:

> _Contradicts ADR-0003 (mTLS identity), but worth reopening because…_
