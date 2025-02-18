![alt text](https://github.com/EnzoFanAccount/SBOMbardier/blob/main/SBOMbardier.png?raw=true)


[![Project Status: WIP](https://img.shields.io/badge/status-early_development-orange)](https://github.com/yourorg/sbombardier)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPLv3-blue.svg)](https://opensource.org/license/agpl-v3)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](CONTRIBUTING.md)

An open-source, community-driven, AI-powered tool to automate Software Bill of Materials (SBOM) validation, license compliance, and vulnerability detection for open-source dependencies.

> **Early Stage Notice**: SBOMbardier is currently in active early development. We welcome contributors and early adopters to help shape its future! We are in need of testers to ensure the tool's functionality!

## Current Core Capabilities (v0.1.1-alpha)

**SBOM Generation & Validation**
- Supports both SPDX and CycloneDX formats
- Integrates with multiple scanners (Syft, Trivy) for comprehensive dependency detection
- Resolves transitive dependencies through package manager integration
- Supports multiple package managers:
  - Python (pip)
  - Node.js (npm)
  - Java (Maven)
  - Gradle
- Validates against NTIA minimum requirements
- Supports CISA standards
- Checks for:
  - Component completeness
  - Required fields
  - License information
  - Package URLs (purls)

**AI/ML Risk Analysis**
- Hybrid risk prediction model (CNN for code structure + GNN for dependency graphs)
- Vulnerability correlation across NVD/OSV databases
- License conflict detection using SPDX compatibility matrix
- Code-to-image conversion pipeline for ML analysis (64x64 grayscale syntax/AST images)

**Platform Foundations**
- FastAPI backend with Redis caching and PostgreSQL storage
- Placeholder Frontend
- Initial CI/CD integration via GitHub Actions plugin
- Docker/Kubernetes deployment scaffolding

## Installation

### Prerequisites
- Python 3.10+ (Backend)
- Node.js 18+ (Frontend)
- Docker 24+ (Container deployment)
- Syft 1.0+ and Trivy 0.50+ (SBOM generation)

### Backend Setup

1. Clone the repository:
```bash
git clone https://github.com/EnzoFanAccount/SBOMbardier.git
cd SBOMbardier
```
2. Install Python dependencies
```bash
cd backend
pip install -r requirements.txt
```
3. Install external tools:
- [Syft](https://github.com/anchore/syft#installation)
- [Trivy](https://aquasecurity.github.io/trivy/latest/getting-started/installation/)

### Frontend Setup

1. Install Node.js dependencies:
```bash
cd frontend
npm install
```
## Usage

### Starting the Backend Service

1. Start the FastAPI server:
```bash
cd backend
python -m sbombardier.main
```
The backend service will be available at `http://localhost:8000`.

### Starting the Frontend Development Server

1. Start the Vite development server:
```bash
cd frontend
npm run dev
```
The frontend will be available at `http://localhost:5173`.

### API Endpoints

#### Generate SBOM
```http
POST /generate
Content-Type: application/json

{
    "format": "cyclonedx", // or "spdx"
    "project_path": "/path/to/project"
}
```
#### Validate SBOM
```http
POST /validate
Content-Type: application/json

{
    "standard": "ntia", // or "cisa"
    "sbom_content": "..." // SBOM content as string
}
```
#### Predict Component Risk
```http
POST /predict-risk
Content-Type: application/json
{
    "name": "package-name",
    "version": "1.0.0",
    "license_id": "MIT",
    "repo_url": "https://github.com/org/repo" // optional
}
```
### Docker Deployment

1. Build the containers:
```bash
docker compose build
```
2. Start the services:
```bash
docker compose up -d
```
The application will be available at `http://localhost:8000` (API) and `http://localhost:80` (Frontend).

## Roadmap 🗺️

### Phase 1: Automated SBOM Generation & Validation | AI-Driven Risk Prediction
- [x] Automated SBOM Generation with Syft
- [x] SBOM validation with SPDX Tools and CycloneDX Validator
- [x] Custom validators for NTIA/CISA
- [x] AI base
- [x] License compatibility matrix
- [ ] Confidence Calibration on Risk Models

### Phase 2: Compliance Workflow Automation | Cross-Platform Ecosystem
- [ ] CI/CD Integration
- [ ] Audit and Reporting
- [ ] Cloud/GRC Integrations
- [ ] IDE Plugins

### Phase 3: Community-Driven Rule Library
- [ ] Collaboration Platform
- [ ] Rule Database
- [ ] Vulnerability Curation

### Phase 4: Deployment
- [ ] Complete Frontend
- [ ] Web Deployment


## Contributing 👋

We urgently need help with:
- Improving ML model accuracy and confidence calibration
- Frontend
- General Testing and Usage

See our [Contributor Guide](CONTRIBUTING.md) for:
- Good first issues
- Development environment setup
- Community standards

## License

AGPL-3.0 - See [LICENSE](LICENSE) for details

> **Special Note for Early Adopters**: Your feedback is crucial! Please open issues for:
> - Missing critical features
> - Documentation gaps
> - Model performance concerns
> - Errors