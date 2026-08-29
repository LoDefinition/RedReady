# Contributing to RedReady

Thanks for helping improve RedReady.

## Before you start

- Search existing issues and pull requests before opening a new one.
- Discuss substantial features or architectural changes in an issue first.
- Never include real target data, credentials, or unauthorized scan output in issues, tests, or commits.

## Development

Use Python 3.11 or 3.12 and install the development dependencies:

```bash
pip install -e ".[dev]"
ruff check .
ruff format --check .
mypy redready tests
pytest -q
```

Write focused tests for changes in behavior. Unit tests must not contact the public internet; mark opt-in network tests with `@pytest.mark.integration`.

## Pull requests

Keep PRs small and explain the problem, approach, tests, and any operational or security impact. Update documentation and migrations when a user-visible interface or schema changes. Do not commit generated scan databases, reports, API keys, or private target details.

## Security reports

Do not open a public issue for a suspected vulnerability. Follow [SECURITY.md](SECURITY.md) instead.