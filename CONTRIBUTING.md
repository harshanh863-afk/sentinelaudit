# Contributing to SentinelAudit

## Code of Conduct

This project is committed to providing a welcoming, inclusive, and
harassment-free experience for everyone. We expect all contributors to
treat each other with respect.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/your-username/SentinelAudit.git`
3. Set up the development environment (see README.md)
4. Create a feature branch: `git checkout -b feature/my-feature`
5. Make your changes
6. Run tests: `cd backend && pytest` (backend), `cd frontend && npm test` (frontend)
7. Push and open a pull request

## Project Structure

```
sentinelaudit/
├── backend/       — FastAPI REST API (Python)
│   └── app/
│       ├── core/        — Config, security, middleware
│       ├── api/v1/      — Versioned API endpoints
│       ├── models/      — SQLAlchemy ORM models
│       ├── schemas/     — Pydantic validation schemas
│       ├── services/    — Business logic
│       └── db/          — Database session management
├── frontend/      — React 18 SPA (TypeScript, Vite)
├── scanner/       — Standalone scanner package
│   └── sentinelaudit_scanner/
│       ├── core/        — Engine, protocols
│       └── checks/      — Modular security checks
├── rules/         — YAML rule definitions
├── reports/       — Generated report output
├── tests/         — Backend, scanner, and integration tests
└── docs/          — Documentation
```

## Coding Standards

### Python (Backend)
- Python 3.11+ type annotations on all functions
- Black-compatible formatting (88 char lines)
- SQLAlchemy 2.0-style queries (no legacy `Query` API)
- Pydantic v2 models for all API schemas
- Use `Optional[T]` instead of `T | None` for consistency

### TypeScript (Frontend)
- TypeScript strict mode, no `any` types
- React functional components with hooks
- shadcn/ui components for UI primitives
- TanStack Query for server state management
- Framer Motion for animations

### Scanner (Python)
- Pure Python, no external scanning dependencies
- All checks return `ScannerObservation` objects
- YAML-driven rule definitions only — no hardcoded checks
- Confidence-based observations (never "confirmed secrets")

## Pull Request Process

1. Ensure all tests pass
2. Add tests for new functionality
3. Update documentation if APIs or behavior change
4. Keep PRs focused on a single concern
5. PRs require at least one review before merging

## Issue Reporting

- Bug reports: include steps to reproduce, expected vs actual behavior,
  environment details (OS, Python version, browser)
- Feature requests: describe the problem you want to solve, not just
  the solution you have in mind
- Security vulnerabilities: see SECURITY.md

## License

By contributing, you agree that your contributions will be licensed
under the MIT License.
