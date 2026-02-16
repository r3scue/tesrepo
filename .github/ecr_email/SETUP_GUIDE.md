# Quick Setup Guide - Jira Integration

## Prerequisites

- ✅ Jira Cloud account with admin access
- ✅ GitHub repository with Actions enabled
- ✅ AWS ECR repository with images

## Step 1: Create Jira API Token

1. Log in to your Jira Cloud instance
2. Click your profile icon → **Account Settings**
3. Navigate to **Security** → **API Tokens**
4. Click **Create API Token**
5. Name it: `GitHub Actions ECR Scanner`
6. Copy the token immediately (you won't see it again!)
7. Store it securely (you'll add it to GitHub Secrets next)

## Step 2: Configure GitHub Secrets

1. Go to your GitHub repository
2. Navigate to **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. Add these secrets:

### Required Secrets

| Secret Name | Value | Example |
|-------------|-------|---------|
| `JIRA_URL` | Your Jira instance URL | `https://your-company.atlassian.net` |
| `JIRA_USERNAME` | Your Jira email | `scanner-bot@company.com` |
| `JIRA_API_TOKEN` | Token from Step 1 | `ATATT3xFfGF0...` |
| `JIRA_PROJECT` | Jira project key | `SEC` |

### Optional Secrets

| Secret Name | Value | Default |
|-------------|-------|---------|
| `JIRA_ISSUE_TYPE` | Issue type name | `Task` |
| `JIRA_EPIC_KEY` | Epic to link tickets | None |
| `JIRA_FAIL_ON_ERROR` | Fail workflow on Jira error | `false` |

## Step 3: Verify Configuration

### Test Jira Connection Locally

```bash
# Clone the repository
git clone <your-repo-url>
cd tesrepo

# Install dependencies
pip install requests boto3

# Set environment variables
export JIRA_URL="https://your-company.atlassian.net"
export JIRA_USERNAME="your-email@company.com"
export JIRA_API_TOKEN="your-token"
export JIRA_PROJECT="SEC"

# Test the script (dry run)
python3 .github/ecr_email/jira_orchestration.py \
  "test-image:1.0.0" \
  "2026-02-17T14:30:00Z" \
  2 \
  5 \
  12 \
  8 \
  "https://github.com/your-org/your-repo/security/code-scanning"
```

Expected output:
```
2026-02-17 14:30:00 - JiraOrchestrator - INFO - Starting Jira orchestration for image: test-image:1.0.0
2026-02-17 14:30:01 - JiraOrchestrator - INFO - Severity counts - Critical: 2, High: 5, Medium: 12, Low: 8
2026-02-17 14:30:02 - JiraOrchestrator - INFO - No existing open ticket found. Creating new ticket.
2026-02-17 14:30:03 - JiraOrchestrator - INFO - Creating new ticket for image: test-image:1.0.0
2026-02-17 14:30:04 - JiraOrchestrator - INFO - Successfully created ticket: SEC-123
2026-02-17 14:30:05 - JiraOrchestrator - INFO - ✅ Jira orchestration completed successfully
```

## Step 4: Run First Scan

### Via GitHub Actions UI

1. Go to **Actions** tab in your repository
2. Select **Scan ECR Image for Vulnerabilities** workflow
3. Click **Run workflow**
4. Enter ECR repository name: `your-repo-name`
5. Click **Run workflow**

### Via GitHub CLI

```bash
gh workflow run image-scan.yml -f ecr_repos=your-repo-name
```

## Step 5: Verify Results

### Check GitHub Actions Log

1. Go to **Actions** tab
2. Click on the running workflow
3. Look for the **Invoke Jira Lifecycle Automation** step
4. Verify output shows:
   ```
   ✅ Jira automation completed successfully for <image-name>
   ```

### Check Jira

1. Go to your Jira project
2. Look for a new ticket with summary:
   ```
   ecr scanner findings - <your-repo-name>:<tag>
   ```
3. Verify ticket details:
   - ✅ Priority set correctly (P0 if Critical > 0, else P1)
   - ✅ Description includes severity split
   - ✅ Labels applied: `ecr-scan`, `security`, `container`
   - ✅ GitHub link present

### Check GitHub Security Tab

1. Go to **Security** → **Code scanning**
2. Filter by tool: "MontyCloud Container Scanner"
3. Verify alerts are present

## Step 6: Test Ticket Lifecycle

### Test 1: Rescan (Update)

Run the workflow again with the same repository.

**Expected:**
- ✅ No duplicate ticket created
- ✅ Comment added to existing ticket
- ✅ Metadata in comment

### Test 2: Priority Change

Modify an image to reduce/increase Critical vulnerabilities, then scan.

**Expected:**
- ✅ Priority updated (P0 ↔ P1)
- ✅ Comment shows change

### Test 3: Auto-Close

Fix all Critical and High vulnerabilities, then scan.

**Expected:**
- ✅ Comment added: "Critical and High vulnerabilities are now zero"
- ✅ Ticket automatically closed

### Test 4: New Ticket After Close

Introduce Critical vulnerabilities again, then scan.

**Expected:**
- ✅ New ticket created (closed ticket NOT reopened)
- ✅ New ticket has correct severity

## Common Setup Issues

### Issue: Authentication Failed

**Error:** `401 Unauthorized`

**Solution:**
- Verify `JIRA_API_TOKEN` is correct
- Ensure `JIRA_USERNAME` matches the token owner
- Check token hasn't expired

### Issue: Project Not Found

**Error:** `Project 'SEC' not found`

**Solution:**
- Verify `JIRA_PROJECT` uses the project **key**, not name
- Check user has access to the project
- Ensure project exists

### Issue: Cannot Create Issue

**Error:** `400 Bad Request` or field validation errors

**Solution:**
- Verify `JIRA_ISSUE_TYPE` exists in your project
- Check required fields in Jira project configuration
- Ensure user has "Create Issues" permission

### Issue: Cannot Transition Issue

**Error:** Cannot find closing transition

**Solution:**
- Check workflow logs for available transitions
- Verify user has permission to transition issues
- May need to customize transition detection in script

### Issue: Duplicate Tickets

**Problem:** Multiple tickets for same image

**Solution:**
- Ensure image name includes tag (format: `repo:tag`)
- Check for concurrent workflow runs
- Verify JQL search is working (check logs)

## Advanced Configuration

### Use AWS Secrets Manager

Instead of GitHub Secrets, store credentials in AWS Secrets Manager:

1. Create secret in AWS with structure:
```json
{
  "jira_url": "https://your-company.atlassian.net",
  "jira_username": "your-email@company.com",
  "jira_api_token": "your-token",
  "jira_project": "SEC",
  "jira_issue_type": "Task"
}
```

2. Add IAM permission:
```json
{
  "Effect": "Allow",
  "Action": "secretsmanager:GetSecretValue",
  "Resource": "arn:aws:secretsmanager:*:*:secret:prod/jira/credentials-*"
}
```

3. Set GitHub Secret:
```
JIRA_AWS_SECRET_NAME=prod/jira/credentials
```

### Link to Epic

To automatically link all tickets to an epic:

1. Create an epic in Jira: `SEC-100`
2. Add GitHub Secret:
```
JIRA_EPIC_KEY=SEC-100
```

### Customize Labels

Edit `.github/ecr_email/jira_orchestration.py`:

```python
DEFAULT_LABELS = ['ecr-scan', 'security', 'container', 'your-label']
```

### Change Priority Names

If your Jira uses different priority names:

```python
PRIORITY_P0 = 'Blocker'  # Instead of 'P0'
PRIORITY_P1 = 'High'      # Instead of 'P1'
```

## Next Steps

- ✅ Review [Complete Documentation](.github/ecr_email/JIRA_INTEGRATION.md)
- ✅ Set up monitoring for Jira ticket creation
- ✅ Configure Jira automation rules if needed
- ✅ Train team on new ticket lifecycle
- ✅ Schedule regular API token rotation (90 days)

## Support

If you encounter issues:

1. Check GitHub Actions logs
2. Verify Jira configuration
3. Test script locally
4. Review [troubleshooting guide](.github/ecr_email/JIRA_INTEGRATION.md#troubleshooting)

## Success Checklist

After setup, verify:

- [ ] Jira API token generated and added to GitHub Secrets
- [ ] All required secrets configured
- [ ] Test workflow run completed successfully
- [ ] Ticket created in Jira with correct details
- [ ] GitHub Code Scanning alerts visible
- [ ] Rescan adds comment (no duplicate ticket)
- [ ] Auto-close works when Critical + High = 0
- [ ] Team trained on ticket lifecycle

**Congratulations!** 🎉 Your ECR Scanner → Jira automation is now active!
