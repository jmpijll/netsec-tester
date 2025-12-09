# Contributing to NetSec Tester

Thank you for your interest in contributing to NetSec Tester! This document provides guidelines and information for contributors.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

### Reporting Bugs

Before submitting a bug report:

1. Check the [existing issues](https://github.com/jmpijll/netsec-tester/issues) to avoid duplicates
2. Use the latest version of the software
3. Collect relevant information:
   - Python version (`python --version`)
   - Operating system and version
   - Steps to reproduce the issue
   - Expected vs actual behavior
   - Error messages and stack traces

Submit bug reports using the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md).

### Suggesting Features

We welcome feature suggestions! Before submitting:

1. Check existing issues and discussions for similar suggestions
2. Consider if the feature fits the project's scope
3. Provide a clear use case and description

Submit feature requests using the [feature request template](.github/ISSUE_TEMPLATE/feature_request.md).

### Contributing Code

#### Setup Development Environment

```bash
# Fork and clone the repository
git clone https://github.com/YOUR_FORK/netsec-tester.git
cd netsec-tester

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install development dependencies
pip install -e ".[dev]"
```

#### Making Changes

1. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```

2. **Make your changes** following our coding standards (see below)

3. **Write tests** for new functionality

4. **Run the test suite**:
   ```bash
   pytest
   ```

5. **Run linting and type checking**:
   ```bash
   ruff check src tests
   ruff format src tests
   mypy src
   ```

6. **Commit your changes** with a clear message:
   ```bash
   git commit -m "feat: add new SQL injection pattern for MySQL"
   ```

7. **Push to your fork** and submit a Pull Request

#### Pull Request Guidelines

- Fill out the PR template completely
- Link any related issues
- Ensure all CI checks pass
- Keep PRs focused on a single change
- Update documentation if needed
- Add tests for new features

## Coding Standards

### Python Style

- Follow PEP 8 guidelines
- Use type hints for all function signatures
- Maximum line length: 88 characters (Black compatible)
- Use descriptive variable and function names

### Documentation

- Write docstrings for all public classes and methods
- Use Google-style docstrings
- Update README and docs for user-facing changes

### Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Test additions or changes
- `refactor:` Code refactoring
- `chore:` Maintenance tasks

Examples:
```
feat: add DNS amplification detection module
fix: resolve packet generation error for IPv6
docs: update README with new scenarios
test: add tests for exfiltration modules
```

### Adding New Modules

When adding traffic modules:

1. Place in the appropriate category directory under `src/netsec_tester/modules/`
2. Inherit from `TrafficModule` base class
3. Implement `get_info()` and `generate_packets()` methods
4. Register in `config/loader.py`
5. Export in the category's `__init__.py`
6. Add comprehensive tests
7. Update documentation

See [DEVELOPMENT.md](docs/DEVELOPMENT.md) for detailed instructions.

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=netsec_tester --cov-report=term-missing

# Run specific test file
pytest tests/test_modules.py

# Run tests matching a pattern
pytest -k "sql_injection"
```

### Writing Tests

- Place tests in the `tests/` directory
- Use pytest fixtures for common setup
- Test both success and failure cases
- Mock external dependencies

## Questions?

- Open a [Discussion](https://github.com/jmpijll/netsec-tester/discussions)
- Check existing documentation
- Review closed issues for similar questions

Thank you for contributing! 🔐

