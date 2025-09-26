# Contributing to OWASP Top 10 Security Scanner

Thank you for your interest in contributing to this project! We welcome contributions from the cybersecurity community.

## Ways to Contribute

### 🐛 Bug Reports
- Use the GitHub issue tracker
- Include system information (OS, Python version, nmap version)
- Provide steps to reproduce the issue
- Include relevant error messages or logs

### 🚀 Feature Requests
- Check existing issues first
- Describe the feature and its use case
- Explain how it aligns with OWASP Top 10 standards

### 💻 Code Contributions
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Follow the coding standards below
4. Add tests for new functionality
5. Update documentation as needed
6. Submit a pull request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/SiteQ8/owasp-top-10-scanner.git
cd owasp-top-10-scanner

# Install dependencies
pip install -r requirements.txt
sudo apt-get install nmap  # Linux

# Run tests
python test_scanner.py
```

## Coding Standards

### Python Style
- Follow PEP 8 guidelines
- Use meaningful variable and function names
- Add docstrings for all functions and classes
- Maximum line length: 127 characters

### Security Considerations
- Always validate user input
- Use secure coding practices
- Never hardcode credentials or sensitive data
- Follow responsible disclosure principles

### Documentation
- Update README.md for new features
- Add inline comments for complex logic
- Include usage examples
- Update CHANGELOG.md

## Vulnerability Detection Guidelines

### Adding New OWASP Checks
1. Research the vulnerability type thoroughly
2. Implement non-destructive detection methods
3. Minimize false positives
4. Add severity classification
5. Include remediation advice

### Testing Standards
- Test against known vulnerable applications (DVWA, WebGoat, etc.)
- Verify against false positive scenarios
- Test with different target types (web apps, APIs, etc.)
- Ensure backwards compatibility

## Submission Guidelines

### Pull Request Process
1. Update the README.md with details of changes if applicable
2. Update the version number in relevant files
3. Ensure all tests pass
4. Request review from maintainers

### Commit Messages
Use conventional commit format:
- `feat:` new features
- `fix:` bug fixes  
- `docs:` documentation changes
- `style:` formatting changes
- `refactor:` code refactoring
- `test:` adding tests
- `chore:` maintenance tasks

Example: `feat: add LDAP injection detection for A03 category`

## Code Review Process

### What We Look For
- Security best practices
- Code quality and readability
- Test coverage
- Documentation completeness
- Performance impact

### Review Timeline
- We aim to review PRs within 48 hours
- Complex changes may take longer
- Please be patient and responsive to feedback

## Getting Help

### Resources
- [OWASP Top 10 Documentation](https://owasp.org/www-project-top-ten/)
- [Nmap Documentation](https://nmap.org/book/)
- [Python Security Guidelines](https://python.org/dev/security/)

### Contact
- GitHub Issues: For bugs and feature requests
- Email: site@hotmail.com (project maintainer)
- Security Issues: Please report privately via email

## Recognition

Contributors will be acknowledged in:
- README.md contributors section
- Release notes
- Git commit history

## Legal Considerations

### Responsible Disclosure
- Only test against systems you own or have permission to test
- Report vulnerabilities through proper channels
- Do not use this tool for malicious purposes

### License
By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for helping make the internet a safer place! 🛡️
