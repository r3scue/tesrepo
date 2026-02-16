# ECR Scanner with Jira Integration

## Overview

This repository contains a **production-ready GitHub Actions workflow** that:

1. ✅ Builds Docker images
2. ✅ Scans ECR images using Trivy
3. ✅ Generates SARIF reports
4. ✅ Uploads to GitHub Code Scanning
5. ✅ Generates CycloneDX SBOM
6. ✅ Enriches dependency relationships
7. ✅ **Automatically manages Jira tickets** for vulnerability findings

## 🆕 Jira Lifecycle Automation

The Jira integration provides **enterprise-grade automated ticket management** with the following capabilities:

### Key Features

- ✅ **Tickets created for all scans** (regardless of severity)
- ✅ **No duplicate active tickets** per image
- ✅ **Severity changes update priority** automatically
- ✅ **Subsequent scans append structured comments**
- ✅ **Tickets auto-close** when Critical and High = 0
- ✅ **Closed tickets are never reopened**
- ✅ **If closed and vulnerabilities reappear** → create new ticket
- ✅ **Multiple ECR repos supported**
- ✅ **Metadata stored in structured format**
- ✅ **System is idempotent** (safe to run multiple times)

### Quick Start

1. **Set up GitHub Secrets:**
   - `JIRA_URL` - Your Jira Cloud instance URL
   - `JIRA_USERNAME` - Your Jira username/email
   - `JIRA_API_TOKEN` - Your Jira API token
   - `JIRA_PROJECT` - Your Jira project key

2. **Run the workflow:**
   ```bash
   # Via GitHub Actions UI: Actions → Scan ECR Image → Run workflow
   # Or via GitHub CLI:
   gh workflow run image-scan.yml -f ecr_repos=your-repo-name
   ```

3. **Check Jira:**
   - Tickets will be automatically created/updated
   - Priority managed based on Critical vulnerabilities
   - Auto-closed when Critical + High = 0

### Documentation

📖 **[Complete Jira Integration Documentation](.github/ecr_email/JIRA_INTEGRATION.md)**

This includes:
- Detailed architecture
- Configuration guide
- All ticket lifecycle scenarios
- Troubleshooting
- Security best practices

## Workflow Structure

```
.github/
├── workflows/
│   ├── image-scan.yml          # Main scanning workflow
│   ├── codeql.yml              # CodeQL analysis
│   └── dependency-review.yml   # Dependency review
└── ecr_email/
    ├── jira_orchestration.py   # ✨ Jira automation script
    ├── JIRA_INTEGRATION.md     # 📖 Detailed documentation
    ├── extract_container_deps.py
    └── enrich_python_vulnerabilities.py
```

## Requirements

- Python 3.11+
- AWS credentials (OIDC or keys)
- Trivy (installed automatically)
- Jira Cloud account (for Jira integration)

## Configuration

### Required GitHub Secrets

| Secret | Description | Required |
|--------|-------------|----------|
| AWS credentials | Via OIDC or access keys | ✅ Yes |
| `JIRA_URL` | Jira Cloud instance URL | ✅ Yes (for Jira) |
| `JIRA_USERNAME` | Jira email/username | ✅ Yes (for Jira) |
| `JIRA_API_TOKEN` | Jira API token | ✅ Yes (for Jira) |
| `JIRA_PROJECT` | Jira project key | ✅ Yes (for Jira) |
| `JIRA_ISSUE_TYPE` | Issue type name | Optional (default: Task) |
| `JIRA_EPIC_KEY` | Epic to link tickets | Optional |

### Optional Configuration

| Secret | Description | Default |
|--------|-------------|---------|
| `JIRA_FAIL_ON_ERROR` | Fail workflow if Jira fails | `false` |
| `JIRA_AWS_SECRET_NAME` | AWS Secrets Manager secret | Not used |

## Usage

### Scan Single Repository

```bash
gh workflow run image-scan.yml -f ecr_repos=my-app
```

### Scan Multiple Repositories

```bash
gh workflow run image-scan.yml -f ecr_repos=app1,app2,app3
```

### View Results

1. **GitHub Security Tab:**
   - Navigate to **Security** → **Code scanning**
   - Filter by tool: "MontyCloud Container Scanner"

2. **Jira:**
   - Check your configured project
   - Look for tickets: `ecr scanner findings - <image-name>`

## Ticket Lifecycle Examples

### Example 1: First Scan
```
Input: payments-api:1.4.3 (Critical: 2, High: 5)
Result: Create ticket with priority P0
```

### Example 2: Rescan (Same)
```
Input: payments-api:1.4.3 (Critical: 2, High: 5)
Result: Add comment to existing ticket
```

### Example 3: Severity Fixed
```
Input: payments-api:1.4.3 (Critical: 0, High: 0)
Result: Add comment + Auto-close ticket
```

### Example 4: Vulnerabilities Return
```
Input: payments-api:1.4.3 (Critical: 3)
Result: Create NEW ticket (don't reopen closed)
```

## Non-Breaking Guarantee

⚠️ **Important:** The Jira integration is **completely additive** and does not modify any existing functionality:

- ✅ SARIF generation unchanged
- ✅ SBOM logic unchanged
- ✅ GitHub Code Scanning upload unchanged
- ✅ All existing reports still generated
- ✅ Workflow continues even if Jira fails (by default)

## Troubleshooting

### Common Issues

1. **No tickets created:**
   - Verify GitHub Secrets are set
   - Check workflow logs for authentication errors

2. **Duplicate tickets:**
   - Ensure image name includes tag
   - Check for concurrent workflow runs

3. **Tickets not closing:**
   - Verify user has transition permissions
   - Check Jira workflow configuration

For detailed troubleshooting, see the [complete documentation](.github/ecr_email/JIRA_INTEGRATION.md#troubleshooting).

## Security

- ✅ Credentials stored in GitHub Secrets or AWS Secrets Manager
- ✅ Never committed to repository
- ✅ API tokens should be rotated every 90 days
- ✅ Uses least-privilege IAM roles
- ✅ Audit logging enabled in Jira

## Support

For issues or questions:

1. Review the [detailed documentation](.github/ecr_email/JIRA_INTEGRATION.md)
2. Check GitHub Actions workflow logs
3. Verify Jira configuration and permissions
4. Test script locally for debugging

## License

Copyright 2026. All rights reserved.
