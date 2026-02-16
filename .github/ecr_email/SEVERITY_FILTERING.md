# Severity Filtering for GitHub Code Scanning

## Overview

The workflow now supports **configurable severity filtering** for vulnerabilities uploaded to GitHub Code Scanning. This allows you to control which severity levels appear in your Security tab while maintaining full reporting elsewhere.

---

## Quick Start

### When Running the Workflow

1. Go to **Actions** → **Scan ECR Image for Vulnerabilities**
2. Click **Run workflow**
3. Select severity filter from dropdown:
   - `CRITICAL` - Only critical vulnerabilities
   - `CRITICAL,HIGH` - Critical and High only
   - `CRITICAL,HIGH,MEDIUM` - Critical, High, and Medium (default)
   - `CRITICAL,HIGH,MEDIUM,LOW` - All vulnerabilities

4. Enter ECR repository name and run

---

## What Gets Filtered

### ✅ Filtered (GitHub Code Scanning Only)
- **GitHub Security Tab** - Only shows selected severities
- **Code Scanning Alerts** - Filtered by your selection
- **Security Dashboard** - Shows only selected levels

### ✅ NOT Filtered (Full Data Preserved)
- **trivy-report.json** - Full unfiltered scan results
- **Artifacts** - Both full and filtered SARIF uploaded
- **CSV Export** - All severities included
- **Jira Integration** - All vulnerabilities tracked
- **Workflow Summary** - Shows all counts

---

## Common Use Cases

### Focus on Critical Issues Only
```yaml
severity_filter: "CRITICAL"
```
**Use when:**
- High-volume environments with many findings
- Want to prioritize only the most severe issues
- Compliance requires tracking only critical CVEs

### Production Standard (Critical + High)
```yaml
severity_filter: "CRITICAL,HIGH"
```
**Use when:**
- Production environments
- Security policy requires immediate action on HIGH+
- Want to reduce noise while maintaining security posture

### Development Standard (Default)
```yaml
severity_filter: "CRITICAL,HIGH,MEDIUM"
```
**Use when:**
- Development and staging environments
- Want visibility into medium-risk issues
- Balanced approach to security monitoring

### Full Visibility
```yaml
severity_filter: "CRITICAL,HIGH,MEDIUM,LOW"
```
**Use when:**
- Comprehensive security audit
- Pre-release security review
- Need complete vulnerability landscape

---

## Changing the Default

### Option 1: Modify Workflow File
Edit `.github/workflows/image-scan.yml`:

```yaml
severity_filter:
  description: "Severity levels to include in Code Scanning"
  required: false
  default: "CRITICAL,HIGH,MEDIUM"  # ← Change this line
  type: choice
```

### Option 2: Set Per-Run
Select different option each time you run the workflow (no code changes needed)

---

## How It Works

### Workflow Steps

```
1. Trivy Scan
   ↓
2. Generate Full SARIF (all severities)
   ↓
3. Enhance SARIF (add metadata)
   ↓
4. Filter SARIF by Selected Severities ← New Step
   ↓
5. Upload Filtered SARIF to Code Scanning
   ↓
6. Upload Both Full & Filtered as Artifacts
```

### Filtering Logic

The filter:
1. Reads your severity selection
2. Extracts severity from each vulnerability's message
3. Keeps only vulnerabilities matching your selection
4. Removes unused rules (cleanup)
5. Adds metadata about filtering applied
6. Validates the filtered SARIF

### Example Output

```
🔍 Filtering SARIF for Code Scanning upload...
   Selected severities: CRITICAL,HIGH,MEDIUM

📊 Filtering Results:
   Original vulnerabilities: 187
   After filtering: 42
   Removed (lower severity): 145

📋 Filtered SARIF Severity Breakdown:
   CRITICAL: 8
   HIGH: 19
   MEDIUM: 15
```

---

## Artifacts Available

After each workflow run, you can download:

| Artifact | Content | Use Case |
|----------|---------|----------|
| `trivy-sarif-full` | All vulnerabilities | Complete audit, historical analysis |
| `trivy-sarif-filtered` | Filtered by selection | What was sent to Code Scanning |
| `trivy-report` | JSON with all data | Detailed analysis, custom reporting |
| `trivy-csv` | CSV with all data | Excel analysis, data processing |

---

## Comparison: Before vs After Filtering

### Example: Medium Noise Environment

**Before Filtering:**
- Security tab: 187 alerts
- Signal-to-noise: Low
- Team overwhelmed
- Critical issues buried

**After Filtering (CRITICAL,HIGH only):**
- Security tab: 27 alerts
- Signal-to-noise: High
- Team focused
- Critical issues visible

**Full data still available:**
- Artifacts: All 187 vulnerabilities
- JSON report: Complete details
- Jira: Tracks all levels

---

## FAQ

### Q: Will filtering affect Jira tickets?
**A:** No. Jira integration uses the vulnerability counts from the JSON report, which includes all severities regardless of your filter selection.

### Q: Can I see what was filtered out?
**A:** Yes. Download the `trivy-sarif-full` artifact to see all vulnerabilities. The workflow also shows filtering statistics in the logs.

### Q: What if I want different filters for different repos?
**A:** Run the workflow separately for each repo with different severity filter selections.

### Q: Can I filter by CVE ID or package name?
**A:** Not currently. The filter only supports severity levels. For advanced filtering, download the full SARIF artifact and process it externally.

### Q: Does filtering affect compliance reporting?
**A:** No. Full scan results are preserved in artifacts and reports. The filter only affects what's displayed in GitHub's Security tab.

### Q: Can I automate this with different filters per environment?
**A:** Yes. Create separate workflow files for different environments (production.yml with CRITICAL,HIGH and dev.yml with all levels) or use repository variables.

---

## Best Practices

### 1. **Start Conservative, Expand Later**
- Begin with `CRITICAL,HIGH` 
- Monitor for a few weeks
- Add `MEDIUM` if needed
- Never ignore CRITICAL/HIGH

### 2. **Different Filters for Different Stages**
```
Production:  CRITICAL,HIGH
Staging:     CRITICAL,HIGH,MEDIUM
Development: CRITICAL,HIGH,MEDIUM,LOW
```

### 3. **Regular Full Scans**
- Run with all severities monthly
- Review filtered-out vulnerabilities quarterly
- Adjust filter based on findings

### 4. **Document Your Policy**
- Define severity thresholds in security policy
- Communicate filter choices to team
- Review and adjust annually

### 5. **Monitor Trends**
- Watch for increasing critical counts
- Track time-to-remediation by severity
- Adjust filters if overwhelmed

---

## Troubleshooting

### Issue: No alerts appearing in Security tab

**Check:**
1. Are there vulnerabilities matching your filter?
2. Is the workflow running on the default branch?
3. Check filtering statistics in workflow logs

**Solution:**
- Widen filter temporarily (add MEDIUM or LOW)
- Check `trivy-sarif-full` artifact for actual findings

### Issue: Too many alerts

**Solution:**
- Narrow filter to `CRITICAL,HIGH`
- Focus on critical remediation first
- Gradually add medium severity back

### Issue: Filter not applying

**Check:**
1. Workflow input was specified
2. SARIF filtering step completed successfully
3. Correct SARIF file uploaded (filtered, not full)

**Solution:**
- Check workflow logs for "Filter SARIF by Severity" step
- Verify `trivy-results-filtered.sarif` was created
- Download both artifacts to compare

---

## Advanced: Custom Filtering

If you need filtering beyond severity levels, you can:

1. **Download full SARIF artifact**
2. **Use jq to filter:**
```bash
# Filter by specific CVE
jq '.runs[0].results = [.runs[0].results[] | select(.ruleId == "CVE-2024-1234")]' \
   trivy-results-full.sarif > custom-filtered.sarif

# Filter by package name
jq '.runs[0].results = [.runs[0].results[] | select(.message.text | contains("openssl"))]' \
   trivy-results-full.sarif > custom-filtered.sarif

# Filter by CVSS score (if available)
jq '.runs[0].results = [.runs[0].results[] | select(... custom logic ...)]' \
   trivy-results-full.sarif > custom-filtered.sarif
```

3. **Upload manually:**
```bash
gh api repos/{owner}/{repo}/code-scanning/sarifs \
  --method POST \
  --field sarif=@custom-filtered.sarif
```

---

## Summary

| Feature | Value |
|---------|-------|
| **Default Filter** | `CRITICAL,HIGH,MEDIUM` |
| **Options** | 4 preset choices |
| **Change Method** | Workflow input dropdown |
| **Affects** | GitHub Code Scanning display only |
| **Preserves** | Full data in artifacts and reports |
| **Jira Impact** | None (uses full data) |
| **Artifacts** | Both filtered and full SARIF uploaded |

---

## Next Steps

1. ✅ Run workflow with default filter
2. ✅ Review Security tab alerts
3. ✅ Adjust filter if needed
4. ✅ Download artifacts to see full data
5. ✅ Document your team's filtering policy

**Remember:** Filtering is about focus, not hiding issues. All vulnerabilities are still scanned, reported, and tracked. The filter simply helps you prioritize what's most important in your Security tab.
