## Description

<!-- Describe your changes in detail -->

## Related Issue

<!-- Link to any related issues: Fixes #123, Closes #456 -->

## Type of Change

<!-- Mark the appropriate option with an x -->

- [ ] 🐛 Bug fix (non-breaking change that fixes an issue)
- [ ] ✨ New feature (non-breaking change that adds functionality)
- [ ] 💥 Breaking change (fix or feature that would cause existing functionality to change)
- [ ] 📚 Documentation update
- [ ] 🧪 Test improvement
- [ ] 🔧 Configuration/build change
- [ ] ♻️ Refactoring (no functional changes)

## Changes Made

<!-- List the specific changes made -->

- 
- 
- 

## New Module Checklist

<!-- If adding a new traffic module, complete this section -->

- [ ] Module inherits from `TrafficModule` base class
- [ ] Implements `get_info()` and `generate_packets()` methods
- [ ] Registered in `config/loader.py`
- [ ] Exported in category's `__init__.py`
- [ ] Added to appropriate scenarios in `scenarios.yaml`
- [ ] Unit tests added
- [ ] Documentation updated

## Testing

<!-- Describe how you tested your changes -->

- [ ] Tests pass locally (`pytest`)
- [ ] Linting passes (`ruff check src tests`)
- [ ] Type checking passes (`mypy src`)
- [ ] Manual testing performed

### Test Output

```
# Paste relevant test output here
```

## Documentation

- [ ] README updated (if needed)
- [ ] docs/USAGE.md updated (if needed)
- [ ] docs/DEVELOPMENT.md updated (if needed)
- [ ] Code comments added/updated

## Screenshots (if applicable)

<!-- Add screenshots to help explain your changes -->

## Additional Notes

<!-- Any additional information that reviewers should know -->

## Checklist

- [ ] My code follows the project's style guidelines
- [ ] I have performed a self-review of my code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes

