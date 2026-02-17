# QPKI Community - AI Development Rules

## MANDATORY: Read Before Any Work

This project follows the centralized development methodology defined in:
- `../qpki-enterprise/DEV-METHODOLOGY.md` - Complete workflow
- `../qpki-enterprise/specs/TEMPLATE.md` - Spec template

## Workflow Reminder

```
TICKET → SPEC → REVIEW → TESTS → CODE → ACCEPT → DOCS
```

## Critical Rules (NEVER violate)

1. **No code without approved spec** - Always create spec first, wait for approval
2. **No code without tests** - Write tests before implementation (TDD)
3. **No merge without CI green** - Acceptance tests must pass
4. **No undocumented features** - Update docs after implementation
5. **Strict scope** - Implement ONLY what is in the spec, nothing more

## Tickets & Specs Location

| What | Where |
|------|-------|
| Tickets (Community) | THIS REPO (public) |
| Specs (Community) | `../qpki-enterprise/specs/community/` (private) |

- Create GitHub Issues HERE for community features
- Create specs in qpki-enterprise (centralized, private)

## Where to Implement

| Spec Location | Code & Tests | Docs | Binary |
|---------------|--------------|------|--------|
| `specs/community/` | THIS REPO | `docs/` | `qpki` CLI |
| `specs/enterprise/` | `qpki-enterprise` | `qpki-enterprise/docs/` | `qpki-server`, `qpki-agent` |

If you're working on a spec from `specs/community/`:
- Implement tests and code HERE
- Update docs in `docs/`

## Test Organization

```
post-quantum-pki/
├── internal/
│   └── */*_test.go           ← Unit + integration tests (CI: unit-tests)
└── test/
    └── acceptance/
        └── *_test.go         ← Acceptance tests (CI: acceptance-tests)
```

## Commit Rules

- Never add "Co-Authored-By" lines
- Never add "Generated with Claude Code" footers in PRs
- Use conventional commits: `feat(scope): description`

## When in Doubt

If you're unsure about anything, ASK the user before proceeding.
Do NOT make assumptions about requirements or implementation details.
