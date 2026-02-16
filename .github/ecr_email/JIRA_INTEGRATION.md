# ECR Scanner → Jira Lifecycle Automation

## Overview

This system provides **enterprise-grade automated Jira lifecycle management** for ECR container vulnerability scans. It operates as a **non-breaking additive layer** on top of existing GitHub Actions workflows that perform scanning, SARIF generation, and GitHub Code Scanning uploads.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  GitHub Actions Workflow                     │
│                                                              │
│  1. Build Docker Image                                       │
│  2. Scan with Trivy                                         │
│  3. Generate SARIF                                          │
│  4. Upload to GitHub Code Scanning                          │
│  5. Generate CycloneDX SBOM                                 │
│  6. Enrich Dependencies                                     │
│  7. Count Vulnerabilities by Severity                       │
│                                                              │
│  ┌────────────────────────────────────────────────────┐    │
│  │     8. Invoke Jira Orchestration (NEW)            │    │
│  │        - Non-breaking                              │    │
│  │        - Runs after all existing steps             │    │
│  │        - Fails gracefully if Jira unavailable      │    │
│  └────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
 ┌─────────────────────────────────────────────────────────────┐
 │           Python Jira Orchestration Script                   │
 │                                                              │
 │  • Search for existing open tickets                         │
 │  • Create new tickets on first scan                         │
 │  • Update tickets on subsequent scans                       │
 │  • Upgrade/downgrade priority based on severity            │
 │  • Auto-close when Critical + High = 0                     │
 │  • Never reopen closed tickets                             │
 │  • Track metadata in structured format                     │
 │  • Support multiple ECR repositories                       │
 └─────────────────────────────────────────────────────────────┘
```

## Features

### ✅ Automated Ticket Lifecycle

- **Tickets created for all scans** (regardless of severity)
- **No duplicate active tickets** per image
- **Severity changes update priority** automatically
- **Subsequent scans append structured comments**
- **Tickets auto-close** when Critical and High = 0
- **Closed tickets are never reopened**
- **If closed and vulnerabilities reappear** → create new ticket
- **Multiple ECR repos supported**
- **Metadata stored in structured format**
- **System is idempotent** (safe to run multiple times)

### 🔐 Priority Management

| Condition | Priority |
|-----------|----------|
| `critical_count > 0` | **P0** |
| `critical_count == 0` | **P1** |

Priority is automatically updated on every scan if it changes.

### 🎯 Ticket Identification

Each image gets **at most one OPEN ticket** at a time.

**Ticket Summary Format:**
```
ecr scanner findings - <image-name>
```

**Example:**
```
ecr scanner findings - payments-api:1.4.3
```

Image name includes repository + tag to prevent cross-repo collisions.

### 📊 Metadata Tracking

Metadata is embedded in ticket descriptions and comments as HTML comments:

```html
<!-- scan-meta:
{
  "image": "payments-api:1.4.3",
  "scan_time": "2026-02-17T14:30:00Z",
  "critical": 2,
  "high": 5,
  "medium": 12,
  "low": 8
}
-->
```

This allows the system to:
- Compare severity changes between scans
- Implement idempotent updates
- Track scan history
- Support multi-repo scenarios

## Configuration

### Required GitHub Secrets

| Secret | Description | Example |
|--------|-------------|---------|
| `JIRA_URL` | **Required.** Jira Cloud instance URL | `https://your-company.atlassian.net` |
| `JIRA_USERNAME` | **Required.** Jira username/email | `your-email@company.com` |
| `JIRA_API_TOKEN` | **Required.** Jira API token | `ATATT3xFfGF0...` |
| `JIRA_PROJECT` | **Required.** Jira project key | `SEC` |
| `JIRA_ISSUE_TYPE` | Issue type name | `Task` (default) |
| `JIRA_EPIC_KEY` | Epic to link tickets to | `SEC-123` (optional) |
| `JIRA_FAIL_ON_ERROR` | Fail workflow if Jira fails | `false` (default) |
| `JIRA_AWS_SECRET_NAME` | AWS Secrets Manager secret name | `prod/jira/credentials` (optional) |

### How to Generate Jira API Token

1. Log in to your Jira Cloud instance
2. Go to **Account Settings** → **Security** → **API Tokens**
3. Click **Create API Token**
4. Give it a descriptive name (e.g., "GitHub Actions ECR Scanner")
5. Copy the token immediately (you won't see it again)
6. Add it to GitHub Secrets as `JIRA_API_TOKEN`

### Setting Up GitHub Secrets

1. Navigate to your repository
2. Go to **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. Add each required secret

### Optional: AWS Secrets Manager Integration

Instead of storing credentials in GitHub Secrets, you can use AWS Secrets Manager:

1. Create a secret in AWS Secrets Manager with this structure:
```json
{
  "jira_url": "https://your-company.atlassian.net",
  "jira_username": "your-email@company.com",
  "jira_api_token": "ATATT3xFfGF0...",
  "jira_project": "SEC",
  "jira_issue_type": "Task",
  "jira_epic_key": "SEC-123"
}
```

2. Set the secret name in GitHub Secrets:
```
JIRA_AWS_SECRET_NAME=prod/jira/credentials
```

3. Ensure your GitHub Actions IAM role has permission:
```json
{
  "Effect": "Allow",
  "Action": "secretsmanager:GetSecretValue",
  "Resource": "arn:aws:secretsmanager:*:*:secret:prod/jira/credentials-*"
}
```

## Ticket Lifecycle Behavior

### Scenario 1: First Scan (New Image)

**Input:**
- Image: `payments-api:1.4.3`
- Critical: 2, High: 5, Medium: 12, Low: 8

**Action:**
- ✅ Create new ticket with summary: `ecr scanner findings - payments-api:1.4.3`
- ✅ Set priority to **P0** (critical > 0)
- ✅ Add initial description with severity split
- ✅ Embed metadata in description
- ✅ Add labels: `ecr-scan`, `security`, `container`

---

### Scenario 2: Rescan (Same Severity)

**Input:**
- Same image, same severity counts

**Action:**
- ✅ Find existing open ticket
- ✅ Add comment with current scan results
- ✅ Embed metadata in comment
- ✅ Priority unchanged
- ✅ No duplicate tickets created

---

### Scenario 3: Severity Increases

**Input:**
- Critical: 2 → 5 (increased)

**Action:**
- ✅ Find existing ticket
- ✅ Priority remains **P0**
- ✅ Add comment showing change: `Critical: 2 → 5`
- ✅ Embed updated metadata

---

### Scenario 4: Severity Decreases (Critical → 0)

**Input:**
- Critical: 2 → 0 (fixed)
- High: 5 → 3

**Action:**
- ✅ Find existing ticket
- ✅ Update priority: **P0** → **P1**
- ✅ Add comment showing improvement
- ✅ Ticket remains open (high still > 0)

---

### Scenario 5: Auto-Close (Critical + High = 0)

**Input:**
- Critical: 0, High: 0, Medium: 12, Low: 8

**Action:**
- ✅ Find existing ticket
- ✅ Add comment: "✅ Critical and High vulnerabilities are now zero."
- ✅ Dynamically find closing transition (Done/Resolved/Close)
- ✅ Execute transition to close ticket
- ✅ **Ticket is closed**
- ✅ **No further updates to this ticket**

---

### Scenario 6: Closed Ticket + New Vulnerabilities

**Input:**
- Ticket was previously closed (Critical + High = 0)
- New scan shows: Critical: 3, High: 2

**Action:**
- ✅ Search finds closed ticket (StatusCategory = Done)
- ✅ Treat as if no open ticket exists
- ✅ **Create NEW ticket** with summary: `ecr scanner findings - payments-api:1.4.3`
- ✅ Set priority to **P0**
- ⚠️ **Never reopen closed ticket**

---

### Scenario 7: Multiple ECR Repositories

**Input:**
- Scan `payments-api:1.4.3` (Critical: 2)
- Scan `user-service:2.1.0` (Critical: 0, High: 5)

**Action:**
- ✅ Create ticket: `ecr scanner findings - payments-api:1.4.3` (Priority: P0)
- ✅ Create separate ticket: `ecr scanner findings - user-service:2.1.0` (Priority: P1)
- ✅ Each image has independent ticket lifecycle
- ✅ No collisions between repositories

---

### Scenario 8: First Update (Description Note)

**Input:**
- Ticket exists with only initial description
- First rescan occurs

**Action:**
- ✅ Detect this is first update (no metadata in comments yet)
- ✅ Append note to description:
```
⚠️ NOTE:
The vulnerability count above reflects the initial scan.
Refer to comments for the most recent scan results.
```
- ✅ Add rescan comment
- ✅ Note is appended **only once**

## Idempotency Guarantees

The system is designed to be **completely idempotent**:

| Scenario | Behavior |
|----------|----------|
| Run twice with same data | No duplicate tickets or comments |
| Priority unchanged | No unnecessary API calls |
| Metadata already exists | No duplicate metadata comments |
| Description note exists | Note not appended again |
| Ticket already closed | Never reopened |
| Transient Jira failure | Retry with exponential backoff |

## Error Handling

### Graceful Failures

By default, Jira errors do **NOT** fail the GitHub Actions workflow:

```yaml
JIRA_FAIL_ON_ERROR: false  # Default
```

**Behavior:**
- ✅ Jira connection fails → Log warning, continue workflow
- ✅ Rate limited → Retry with backoff
- ✅ Invalid credentials → Log error, continue workflow
- ✅ SARIF upload still succeeds
- ✅ GitHub Code Scanning alerts still created

### Strict Mode

To fail the workflow on Jira errors:

```yaml
JIRA_FAIL_ON_ERROR: true
```

## Logging

The script provides comprehensive structured logging:

```
2026-02-17 14:30:00 - JiraOrchestrator - INFO - Starting Jira orchestration for image: payments-api:1.4.3
2026-02-17 14:30:01 - JiraOrchestrator - INFO - Severity counts - Critical: 2, High: 5, Medium: 12, Low: 8
2026-02-17 14:30:02 - JiraOrchestrator - INFO - Searching with JQL: project = "SEC" AND summary ~ "ecr scanner findings - payments-api:1.4.3" AND statusCategory != Done ORDER BY created DESC
2026-02-17 14:30:03 - JiraOrchestrator - INFO - Found existing open ticket: SEC-456
2026-02-17 14:30:04 - JiraOrchestrator - INFO - Updating ticket: SEC-456
2026-02-17 14:30:05 - JiraOrchestrator - INFO - Updating priority: P1 → P0
2026-02-17 14:30:06 - JiraOrchestrator - INFO - Successfully updated priority to: P0
2026-02-17 14:30:07 - JiraOrchestrator - INFO - Successfully added rescan comment
2026-02-17 14:30:08 - JiraOrchestrator - INFO - ✅ Jira orchestration completed successfully
```

## Testing

### Manual Testing

You can test the script locally:

```bash
# Set environment variables
export JIRA_URL="https://your-company.atlassian.net"
export JIRA_USERNAME="your-email@company.com"
export JIRA_API_TOKEN="your-api-token"
export JIRA_PROJECT="SEC"

# Run script
python3 .github/ecr_email/jira_orchestration.py \
  "test-image:1.0.0" \
  "2026-02-17T14:30:00Z" \
  2 \
  5 \
  12 \
  8 \
  "https://github.com/your-org/your-repo/security/code-scanning"
```

### Test Scenarios

1. **Create New Ticket:**
   - Run script with a new image name
   - Verify ticket is created in Jira
   - Check priority, labels, description

2. **Update Existing Ticket:**
   - Run script again with same image
   - Verify comment is added (not duplicate ticket)
   - Check metadata in comment

3. **Priority Change:**
   - Run with Critical > 0 (should be P0)
   - Run again with Critical = 0 (should change to P1)
   - Verify priority updated in Jira

4. **Auto-Close:**
   - Run with Critical = 0, High = 0
   - Verify ticket is closed
   - Check closing comment

5. **Closed Ticket + New Vulns:**
   - Close a ticket manually in Jira
   - Run script with same image (Critical > 0)
   - Verify NEW ticket is created (not reopened)

## Customization

### Custom Issue Types

To use a custom issue type (e.g., "Security Issue"):

```yaml
JIRA_ISSUE_TYPE: Security Issue
```

### Custom Epic Linking

To link all tickets to an epic:

```yaml
JIRA_EPIC_KEY: SEC-123
```

### Custom Labels

To modify default labels, edit the script:

```python
# In jira_orchestration.py
DEFAULT_LABELS = ['ecr-scan', 'security', 'container', 'your-custom-label']
```

### Custom Priority Names

If your Jira uses different priority names, edit:

```python
# In jira_orchestration.py
PRIORITY_P0 = 'Blocker'  # Instead of 'P0'
PRIORITY_P1 = 'High'      # Instead of 'P1'
```

### Custom Closing Transitions

The script automatically detects transitions containing:
- "Done"
- "Resolved"
- "Close"

If your workflow uses different names, the script will log available transitions. Update the logic in `close_ticket()` method.

## Troubleshooting

### Issue: No tickets created

**Check:**
1. Verify GitHub Secrets are set correctly
2. Check workflow logs for Jira authentication errors
3. Ensure `JIRA_PROJECT` exists and is accessible
4. Verify API token hasn't expired

### Issue: Duplicate tickets

**Check:**
1. Verify ticket summary format matches exactly
2. Check for multiple concurrent workflow runs
3. Review JQL search query in logs
4. Ensure image name includes tag

### Issue: Priority not updating

**Check:**
1. Verify priority names match your Jira configuration
2. Check if user has permission to edit priority
3. Review logs for API errors

### Issue: Tickets not closing

**Check:**
1. Verify user has permission to transition issues
2. Check available transitions in logs
3. Ensure workflow name matches detection logic
4. Manually verify transition names in Jira

### Issue: AWS Secrets Manager fails

**Check:**
1. Verify IAM role has `secretsmanager:GetSecretValue` permission
2. Check secret name matches exactly
3. Ensure boto3 is installed
4. Review CloudTrail logs for access denied errors

## Security Best Practices

1. **Never commit credentials** to the repository
2. **Use GitHub Secrets** or AWS Secrets Manager
3. **Rotate API tokens** regularly (every 90 days recommended)
4. **Use least-privilege IAM roles** for AWS access
5. **Enable audit logging** in Jira to track automated changes
6. **Review Jira permissions** to ensure bot user has minimal required access

## Maintenance

### Updating the Script

The Python script is located at:
```
.github/ecr_email/jira_orchestration.py
```

After making changes:
1. Test locally first
2. Commit and push to a feature branch
3. Test with `workflow_dispatch` before merging to main

### Monitoring

Monitor the following:

1. **GitHub Actions Logs:** Check for Jira errors
2. **Jira Audit Log:** Review automated ticket changes
3. **GitHub Security Tab:** Verify SARIF uploads succeed
4. **Ticket Quality:** Periodically review created tickets

## Support

For issues or questions:

1. Check GitHub Actions workflow logs
2. Review Jira audit logs
3. Verify configuration in GitHub Secrets
4. Test script locally with debug logging
5. Review this documentation

## Migration Guide

If you have existing tickets:

1. **No action required** - System will find existing open tickets by summary
2. Closed tickets will **not** be reopened
3. New scans will create new tickets if closed
4. Metadata will be tracked going forward

## License

This automation is part of the ECR Scanner project.
