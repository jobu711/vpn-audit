---
created: 2026-03-07T23:56:33Z
last_updated: 2026-03-07T23:56:33Z
version: 1.0
author: Claude Code PM System
---

# Project Style Guide

## Python

- **Style:** Standard Python conventions, no linter config (follows PEP 8 informally)
- **Type hints:** Used in function signatures (e.g., `-> AuditResult`, `list[str] | None`)
- **Docstrings:** Triple-quoted, present on classes and public methods
- **Imports:** stdlib first, then third-party, then local (`from backend.core.models import AuditResult`)
- **Constants:** Module-level with underscore prefix for private (`_DEFAULT_VPN_PATTERNS`, `_API_URL`)
- **Dataclasses:** Used for structured data (`AuditResult`)

## File Naming

- Python modules: `snake_case.py`
- Test files: `test_{module}.py` mirroring source
- Frontend: standard web names (`index.html`, `app.js`, `style.css`)

## Git Conventions

- **Commit format:** `Issue #{number}: {description}`
- **Branching:** `epic/{name}` for feature epics, merged to `main`
- **Merge commits:** `Merge epic: {name}`

## Testing Conventions

- Async tests with `pytest-asyncio` (auto mode)
- External deps (Scapy, psutil, subprocess) always mocked
- Test classes group related scenarios (e.g., `TestPassScenario`, `TestFailScenario`)
- Shared fixture in `conftest.py` for async HTTP client

## Frontend

- Vanilla JS — no frameworks, no build step
- CSS Grid layout, dark theme
- `var` declarations (not `let`/`const`) — consistent with existing code
- Functions use `function` declarations, not arrows

## Code Philosophy

- Minimal changes — don't refactor what you don't need to
- No unnecessary abstractions
- Follow existing patterns in the codebase
- Always run tests before committing
