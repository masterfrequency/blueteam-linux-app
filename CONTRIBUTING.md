# Contributing to BlueTeam

Thank you for your interest in contributing to BlueTeam! We welcome contributions from the community.

## Code of Conduct

Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before contributing.

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/masterfrequency/blueteam-linux-app/issues)
2. If not, create a new issue with:
   - Clear description of the bug
   - Steps to reproduce
   - Expected behavior
   - Actual behavior
   - Environment details (OS, Python version, etc.)

### Suggesting Features

1. Check if the feature has been suggested in [Discussions](https://github.com/masterfrequency/blueteam-linux-app/discussions)
2. Create a discussion with:
   - Clear description of the feature
   - Use case and benefits
   - Possible implementation approach

### Submitting Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Add tests for new functionality
5. Run tests: `pytest`
6. Commit with clear messages: `git commit -m "Add feature: description"`
7. Push to your fork: `git push origin feature/your-feature`
8. Create a Pull Request with:
   - Clear description of changes
   - Link to related issues
   - Screenshots if applicable

## Development Setup

```bash
# Clone repository
git clone https://github.com/masterfrequency/blueteam-linux-app.git
cd blueteam-linux-app

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
pytest

# Run linting
flake8 .
black .
mypy .
```

## Code Standards

- Follow PEP 8 style guide
- Use type hints for all functions
- Write docstrings for all modules and functions
- Maintain 80%+ test coverage
- Use meaningful variable and function names

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test file
pytest tests/test_modules.py

# Run specific test
pytest tests/test_modules.py::TestNetworkModules::test_ai_traffic_analyzer
```

## Documentation

- Update README.md for user-facing changes
- Update API.md for API changes
- Add docstrings to all new code
- Update CHANGELOG.md

## Commit Messages

Use clear, descriptive commit messages:

```
Add feature: Brief description

Longer description of the change if needed.
Explain why this change was made.

Fixes #123
```

## Pull Request Process

1. Update documentation
2. Add tests for new functionality
3. Ensure all tests pass
4. Request review from maintainers
5. Address feedback
6. Maintainer will merge when approved

## Code Review

All submissions require review. We look for:

- Code quality and style
- Test coverage
- Documentation
- Performance impact
- Security implications

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Questions?

- Open a [Discussion](https://github.com/masterfrequency/blueteam-linux-app/discussions)
- Email: support@blueteam.io
- Join our [Slack community](https://blueteam-community.slack.com)

Thank you for contributing to BlueTeam!
