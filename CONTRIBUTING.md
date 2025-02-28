# Contributing to SBOMbardier

First off, thank you for considering contributing to SBOMbardier! It's people like you that make SBOMbardier such a great tool.

## Code of Conduct

By participating in this project, you are expected to uphold our [Code of Conduct](CODE_OF_CONDUCT.md). Please report unacceptable behavior to sbmbrdr@protonmail.com.

## How Can I Contribute?

### Current Priority Areas

We're currently focusing on:
1. Improving ML model accuracy and confidence calibration
2. Frontend development
3. General testing and usage feedback
4. Documentation improvements
5. Policy rule contributions for different compliance frameworks
6. DGL and PyTorch installation

### Reporting Bugs

Before creating bug reports, please check the issue list as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible:

* Use a clear and descriptive title
* Describe the exact steps which reproduce the problem
* Provide specific examples to demonstrate the steps
* Describe the behavior you observed after following the steps
* Explain which behavior you expected to see instead and why
* Include any error messages or logs

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

* A clear and descriptive title
* A step-by-step description of the suggested enhancement
* Any possible drawbacks
* The current and suggested behavior
* Why this enhancement would be useful

### Pull Requests

1. Fork the repo and create your branch from `main`
2. If you've added code that should be tested, add tests
3. If you've changed APIs, update the documentation
4. Ensure the test suite passes
5. Make sure your code lints
6. Issue that pull request!

## Development Setup

### Backend Development

1. Set up Python environment:
```bash
# Install Poetry (if not already installed)
pip install poetry

# Install dependencies
cd backend
poetry install --extras "ml compliance"  # Install all dependencies for development

# Activate virtual environment
poetry shell
```

2. ML Dependencies (important for ML feature development): The ML features in SBOMbardier depend on PyTorch and DGL (Deep Graph Library), which require specific version compatibility:
```bash
# Use our helper script to install compatible ML dependencies
python install_ml_deps.py
```
This script installs PyTorch 2.0.1 and DGL 1.1.2, which are tested and known to work well together, especially on Windows platforms. Important ML Development Notes:
* ML features are designed to gracefully degrade if dependencies are missing
* Always test your code with and without ML dependencies available
* Check conditional imports in ```risk/predictor.py``` and ```ml/models/risk_models.py```
* When adding new ML features, ensure they have fallback mechanisms

3. Install external tools:
- [Syft](https://github.com/anchore/syft#installation)
- [Trivy](https://aquasecurity.github.io/trivy/latest/getting-started/installation/)

4. Run tests:
```bash
poetry run pytest
```

### Frontend Development

1. Set up Node.js environment:
```bash
cd frontend
npm install
```

2. Start development server:
```bash
npm run dev
```

## Project Structure

```
sbombardier/
├── backend/
│   ├── sbombardier/
│   │   ├── core/           # Main SBOM generation logic
│   │   ├── scanners/       # Integration with Syft and Trivy
│   │   ├── validators/     # SBOM validation logic
│   │   ├── utils/          # Package manager integration
│   │   └── ml/             # ML models and training
│   └── tests/
├── frontend/
│   ├── src/
│   │   ├── components/     # React components
│   │   ├── pages/          # Page components
│   │   └── lib/            # Utilities and helpers
│   └── tests/
└── docs/                    # Documentation
```

## Coding Style

### Python
- Follow PEP 8
- Use type hints
- Document functions and classes using docstrings
- Maximum line length of 100 characters

### TypeScript/React
- Follow ESLint configuration
- Use functional components with hooks
- Use TypeScript types/interfaces
- Follow project's component structure

## Cross-Platform Compatibility

SBOMbardier aims to work across Windows, macOS, and Linux platforms. When contributing, please keep these considerations in mind:

### Dependencies
- Some ML libraries have platform-specific compatibility requirements
- Always test your code on multiple platforms when possible
- For Windows compatibility:
  - Prefer pinned versions of PyTorch (2.0.1) and DGL (1.1.2)
  - Make sure TensorFlow dependencies use the supported version (2.10.0)

### Conditional Imports
- Use try/except blocks for optional dependencies
- Include helpful error messages when a library isn't available
- Implement graceful fallbacks for all ML-dependent features
- Test both with and without all optional dependencies installed

### File Paths
- Use `pathlib.Path` for cross-platform path handling instead of string manipulation
- Avoid hardcoded path separators (e.g., use `Path.joinpath()` instead of `path + '/'`)
- Consider case sensitivity differences between platforms

## Testing

- Write unit tests for new features
- Ensure all tests pass before submitting PR
- Include integration tests where appropriate
- Test edge cases and error conditions

## Documentation

- Update README.md if needed
- Add docstrings to Python functions
- Comment complex algorithms
- Update API documentation for changes
- Include examples for new features

## Questions?

Feel free to open an issue with your question or reach out to the maintainers directly.

## License

By contributing, you agree that your contributions will be licensed under the AGPL-3.0 License. 