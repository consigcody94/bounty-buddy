# Contributing to IoTHackBot

Thank you for your interest in contributing to IoTHackBot! This document provides guidelines and instructions for contributing.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Remember this is a security tool - ensure all contributions follow ethical guidelines
- Only test systems you own or have explicit permission to test

## Getting Started

### Development Setup

1. **Fork and clone the repository**
```bash
git clone https://github.com/YourUsername/iothackbot.git
cd iothackbot
```

2. **Create a virtual environment**
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install development dependencies**
```bash
pip install -r requirements-dev.txt
```

4. **Install pre-commit hooks**
```bash
pre-commit install
```

5. **Run tests to verify setup**
```bash
pytest tests/ -v
```

## Development Workflow

### Creating a New Tool

Follow the architecture pattern described in `TOOL_DEVELOPMENT_GUIDE.md`:

1. **Create core implementation** in `tools/iothackbot/core/`
2. **Create CLI wrapper** in `tools/iothackbot/`
3. **Create binary** in `bin/`
4. **Add tests** in `tests/unit/`
5. **Update documentation**

Example:
```bash
# Create new tool files
touch tools/iothackbot/mytool.py
touch tools/iothackbot/core/mytool_core.py
touch bin/mytool
chmod +x bin/mytool
touch tests/unit/test_mytool_core.py
```

### Code Style

We use several tools to maintain code quality:

- **black**: Code formatting (line length: 100)
- **isort**: Import sorting
- **flake8**: Linting
- **mypy**: Type checking
- **bandit**: Security linting

Format your code before committing:
```bash
black tools/ tests/
isort tools/ tests/
flake8 tools/ tests/
mypy tools/iothackbot
```

Or let pre-commit hooks handle it automatically.

### Writing Tests

All new features must include tests:

- **Unit tests** for core functionality
- **Integration tests** for tool workflows
- Aim for >80% code coverage

Example test structure:
```python
import pytest
from iothackbot.core.mytool_core import MyTool
from iothackbot.core.interfaces import ToolConfig, ToolResult


class TestMyTool:
    def test_tool_properties(self):
        tool = MyTool()
        assert tool.name == "mytool"
        assert tool.description != ""

    def test_tool_execution(self):
        tool = MyTool()
        config = ToolConfig(input_paths=["/test"])
        result = tool.run(config)
        assert isinstance(result, ToolResult)
```

Run tests:
```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=tools/iothackbot

# Run specific test file
pytest tests/unit/test_mytool_core.py -v
```

### Documentation

- Add docstrings to all public functions and classes
- Update README.md with new tool documentation
- Add examples to demonstrate usage
- Update TOOL_DEVELOPMENT_GUIDE.md if adding new patterns

### Commit Messages

Use clear, descriptive commit messages:

```
Add MQTT scanner tool

- Implement core MQTT discovery functionality
- Add CLI interface with authentication support
- Include comprehensive unit tests
- Update documentation with usage examples
```

Format: `<type>: <description>`

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Test additions/changes
- `refactor`: Code refactoring
- `style`: Code style changes
- `chore`: Maintenance tasks

## Pull Request Process

1. **Create a feature branch**
```bash
git checkout -b feature/mqtt-scanner
```

2. **Make your changes**
   - Follow the code style guidelines
   - Add tests for new functionality
   - Update documentation

3. **Run the full test suite**
```bash
pytest tests/ -v --cov=tools/iothackbot
```

4. **Commit your changes**
```bash
git add .
git commit -m "feat: Add MQTT scanner tool"
```

5. **Push to your fork**
```bash
git push origin feature/mqtt-scanner
```

6. **Create a Pull Request**
   - Provide a clear description of changes
   - Reference any related issues
   - Ensure CI checks pass

### PR Checklist

- [ ] Code follows project style guidelines
- [ ] All tests pass locally
- [ ] New tests added for new functionality
- [ ] Documentation updated
- [ ] Commit messages are clear and descriptive
- [ ] No sensitive data (credentials, API keys) in code
- [ ] Tool follows security best practices

## Security Considerations

When contributing security tools:

1. **Never include malicious code**
   - No backdoors, data exfiltration, or intentional vulnerabilities
   - All code should be transparent and auditable

2. **Follow responsible disclosure**
   - Don't include 0-day exploits
   - Reference CVEs for known vulnerabilities

3. **Add safety checks**
   - Rate limiting where appropriate
   - Clear warnings for destructive operations
   - Confirmation prompts for dangerous actions

4. **Test responsibly**
   - Only test against systems you own or have permission
   - Include safety documentation
   - Add disclaimers about authorized use

## Reporting Security Issues

If you discover a security vulnerability in IoTHackBot:

1. **DO NOT** open a public issue
2. Email the maintainers directly (see README for contact)
3. Include detailed information about the vulnerability
4. Allow time for the issue to be addressed before public disclosure

## Questions?

- Open an issue for bug reports or feature requests
- Join our discussions for questions and ideas
- Check existing issues and documentation first

## License

By contributing to IoTHackBot, you agree that your contributions will be licensed under the MIT License.

Thank you for contributing to IoTHackBot!
