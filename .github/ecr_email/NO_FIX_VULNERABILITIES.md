# Handling Vulnerabilities Without Available Patches

## Overview

Container vulnerability scans often discover CVEs that have **no available fix** yet. This document explains how these are handled in the scanning workflow and provides guidance on managing them.

---

## Current Implementation

### Detection & Classification

The workflow automatically detects when a vulnerability has no available patch:

1. **Fixed Version Extraction:**
   - Parses Trivy output for "Fixed Version" field
   - If empty, null, or missing → No fix available
   - If version present → Fix available

2. **Package Type Detection:**
   - OS packages (base image dependencies)
   - Application packages (Python, Node.js, etc.)

3. **Remediation Messaging:**
   ```
   IF fixed_version exists:
     → "Upgrade <package> to version <version> or later"
   
   ELSE IF os_package:
     → "Update the base image or perform system package upgrade"
   
   ELSE:
     → "No patched version currently available. Monitor upstream advisories"
   ```

---

## In GitHub Code Scanning

### Alert Display for No-Fix Vulnerabilities

When you click on an alert with no available patch, you'll see:

```
🛡️ Container Vulnerability

Repository: payments-api
Tag: v1.2.3
Image: 801754344896.dkr.ecr.us-west-2.amazonaws.com/payments-api:v1.2.3

---

📦 Affected Package

- Package: libssl3
- Installed Version: 3.0.2-0ubuntu1.10
- Fixed Version: Not available
- Container Path: /usr/lib/x86_64-linux-gnu/libssl.so.3

---

🔥 Severity: HIGH

---

🛠 Recommended Remediation

No patched version currently available. Monitor upstream advisories.

---

📖 CVE Reference: CVE-2024-xxxxx
```

### Key Indicators

1. **"Fixed Version: Not available"** - Clearly shows no patch exists
2. **Remediation advice** - Explains the situation
3. **Alert stays open** - Won't auto-close until a fix is released
4. **CVE link** - Monitor for updates

---

## Why Vulnerabilities Have No Fix

### Common Reasons

1. **Recently Disclosed (0-day)**
   - CVE just published
   - Vendor working on patch
   - Timeline: Weeks to months

2. **OS Package in Base Image**
   - Requires upstream OS update
   - Waiting for Ubuntu/Debian/Alpine release
   - Timeline: Days to weeks

3. **Abandoned Package**
   - Package no longer maintained
   - No upstream fixes coming
   - Action: Consider alternatives

4. **Disputed/False Positive**
   - Vendor disagrees with CVE
   - May never be fixed
   - Action: Assess actual risk

5. **Requires Major Version Upgrade**
   - Fix only in v2.x, you have v1.x
   - Breaking changes prevent auto-fix
   - Action: Plan migration

---

## Management Strategies

### 1. Risk Assessment

For each no-fix vulnerability:

```
Critical Severity + No Fix = High Priority
├─ Assess exploitability
├─ Check if attack vector applies
├─ Consider compensating controls
└─ Escalate to security team

High/Medium + No Fix = Monitor Closely
├─ Weekly check for patches
├─ Document in risk register
└─ Review alternatives

Low Severity + No Fix = Accept Risk
├─ Document decision
├─ Periodic review (quarterly)
└─ Monitor for severity changes
```

### 2. Action Matrix

| Severity | Package Type | Action |
|----------|-------------|--------|
| **Critical** | Application | Evaluate alternative packages immediately |
| **Critical** | OS Package | Update base image if newer available |
| **Critical** | Any | Implement compensating controls |
| **High** | Application | Search for patched alternatives |
| **High** | OS Package | Check for backported fixes |
| **Medium** | Any | Monitor weekly for patches |
| **Low** | Any | Monitor monthly, document |

### 3. Compensating Controls

When a fix isn't available:

#### Network-Level:
```
- WAF rules to block exploit attempts
- Network segmentation to limit exposure
- Rate limiting to slow attacks
- IPS signatures for known exploits
```

#### Application-Level:
```
- Input validation to prevent exploitation
- Disable vulnerable features if unused
- Runtime protection (AppArmor, SELinux)
- Container security policies
```

#### Monitoring:
```
- Enhanced logging for affected components
- Alert on suspicious activity patterns
- Runtime security monitoring
- Regular penetration testing
```

---

## Workflow Enhancements (Implemented)

### GitHub Code Scanning Display

✅ **Clear Labeling**
- Fixed Version field shows "Not available"
- Distinct from "Unknown" or parsing errors

✅ **Actionable Guidance**
- Specific remediation advice per package type
- Links to CVE details
- Not just "no fix available"

✅ **Persistent Alerts**
- Alerts remain open until fix available
- Not dismissed automatically
- Tracked in Jira alongside fixable issues

### Jira Integration

✅ **All Vulnerabilities Tracked**
- No-fix CVEs included in ticket counts
- Severity affects priority (P0/P1)
- Not hidden or filtered out

✅ **Status Tracking**
- Tickets remain open
- Severity changes update priority
- Auto-close only when ALL critical+high = 0

---

## Proposed Enhancements

### 1. Add "Fixability" Tag

**Current:**
```json
{
  "package": "libssl3",
  "severity": "HIGH",
  "fixed_version": ""
}
```

**Enhanced:**
```json
{
  "package": "libssl3",
  "severity": "HIGH",
  "fixed_version": "",
  "fixable": false,  // ← New field
  "fix_status": "awaiting_upstream"  // ← Status indicator
}
```

### 2. Separate No-Fix Alerts

Add filtering option:
```yaml
show_unfixable: true  # Show even without fixes
                      # false = only show fixable vulns
```

### 3. Aging Tracking

Track how long vulnerabilities remain unfixed:
```
CVE-2024-xxxxx
- Discovered: 30 days ago
- Status: No fix available
- Last checked: 2 hours ago
```

### 4. Auto-Suppress Low/Medium No-Fix

For low-noise environments:
```yaml
suppress_unfixable_severity: 
  - LOW
  - MEDIUM
# Still tracked in reports, just not in Security tab
```

### 5. External Advisory Links

Add links to:
- Vendor security advisories
- Package issue trackers
- Exploit databases
```
📖 CVE Reference: CVE-2024-xxxxx
📋 Vendor Advisory: [OpenSSL Security Advisory]
🐛 Issue Tracker: [GitHub Issue #12345]
```

---

## Best Practices

### For Security Teams

1. **Daily Review**
   - Check for new no-fix CVEs
   - Assess critical/high severity immediately
   - Document risk acceptance decisions

2. **Weekly Status Check**
   - Review all open no-fix alerts
   - Check if patches released
   - Update compensating controls

3. **Monthly Risk Review**
   - Re-assess severity of long-standing issues
   - Evaluate alternative packages
   - Review effectiveness of controls

### For Development Teams

1. **Don't Ignore**
   - No-fix ≠ no risk
   - Review and assess each one
   - Implement controls where possible

2. **Monitor Upstream**
   - Subscribe to package security lists
   - Check vendor advisories weekly
   - Test patches when available

3. **Plan Alternatives**
   - Research replacement packages
   - Evaluate migration effort
   - Consider forking if necessary

### For DevOps Teams

1. **Automate Checks**
   - Daily scans to catch new fixes
   - Alert when patches become available
   - Auto-update when safe

2. **Version Pinning**
   - Pin to specific versions
   - Control update timing
   - Test before promoting

3. **Base Image Strategy**
   - Prefer minimal base images
   - Regularly update base images
   - Consider distroless for reduced surface

---

## FAQ

### Q: Should I dismiss alerts for vulnerabilities with no fix?

**A:** No. Keep them open to:
- Maintain visibility
- Get notified when fix arrives
- Track risk over time
- Comply with audit requirements

### Q: How do I know when a fix becomes available?

**A:** Multiple ways:
1. GitHub Code Scanning auto-updates when re-scanned
2. Jira ticket shows change in next scan
3. Trivy database updates daily
4. Subscribe to CVE/vendor advisories

### Q: Can I filter out no-fix vulnerabilities from Code Scanning?

**A:** Not directly, but you can:
1. Use severity filtering (they still appear at their severity)
2. Download SARIF and custom filter
3. **Proposed:** Add fixability filter (see enhancements above)

### Q: Do no-fix vulnerabilities count toward auto-closing Jira tickets?

**A:** Yes. Jira auto-close only when Critical+High = 0, including no-fix CVEs. This ensures they're not forgotten.

### Q: What if a no-fix vulnerability is a false positive?

**A:**
1. Verify in CVE database
2. Check vendor response
3. Dismiss in GitHub Code Scanning with reason
4. Document in Jira ticket
5. Consider suppression in Trivy config

### Q: Should Production have different handling than Dev?

**A:** Yes, recommended approach:
```
Production:
- Block deployments with Critical no-fix CVEs
- Require risk acceptance sign-off
- Mandatory compensating controls

Development/Staging:
- Allow deployment with documentation
- Monitor for fixes
- Test patches immediately
```

---

## Metrics to Track

### Vulnerability Aging
```
- Average days until fix available
- Longest outstanding no-fix CVE
- Number of no-fix CVEs > 90 days old
```

### Risk Exposure
```
- Critical no-fix count
- High no-fix count
- No-fix CVEs with known exploits
```

### Response Effectiveness
```
- Time to implement compensating controls
- Time to apply fix once available
- False positive rate
```

---

## Example Scenarios

### Scenario 1: Critical No-Fix in Production

**Situation:**
- CVE-2024-xxxxx in OpenSSL 3.0.2
- Severity: CRITICAL
- No fix available
- Production deployment tomorrow

**Response:**
1. ✅ Risk assessment meeting
2. ✅ Check exploit availability and attack vector
3. ✅ Implement WAF rules
4. ✅ Network segmentation
5. ✅ Enhanced monitoring
6. ✅ Document risk acceptance
7. ✅ Deploy with controls
8. ✅ Daily patch checks
9. ✅ Patch within 4 hours of availability

### Scenario 2: Medium No-Fix in Base Image

**Situation:**
- CVE in Ubuntu package
- Severity: MEDIUM
- No fix in current LTS

**Response:**
1. ✅ Check if newer Ubuntu LTS has fix
2. ✅ Check if backport available
3. ✅ Assess actual exploitability
4. ✅ Document in risk register
5. ✅ Weekly monitoring
6. ✅ Proceed with deployment
7. ✅ Update when available

### Scenario 3: High No-Fix in Dependency

**Situation:**
- Python package vulnerability
- Severity: HIGH
- Package maintainer inactive

**Response:**
1. ✅ Search for maintained alternatives
2. ✅ Fork and patch if critical
3. ✅ Implement input validation
4. ✅ Add runtime protection
5. ✅ Plan migration timeline
6. ✅ Communicate to stakeholders

---

## Summary

| Aspect | Current Handling |
|--------|------------------|
| **Detection** | ✅ Automatic via fixed_version check |
| **Display** | ✅ "Not available" shown clearly |
| **Remediation** | ✅ Context-aware advice |
| **Tracking** | ✅ Included in Jira tickets |
| **Filtering** | ✅ Included in severity filter |
| **Artifacts** | ✅ Present in all reports |
| **Auto-Close** | ❌ Prevents premature closure |

**Bottom Line:** All vulnerabilities are tracked and reported, regardless of fix availability. No-fix CVEs are clearly labeled with appropriate remediation guidance, helping teams make informed risk decisions rather than hiding the issues.

---

## Recommendations

1. ✅ **Keep current implementation** - It handles no-fix cases well
2. 💡 **Consider enhancements** - Fixability tags, aging tracking
3. 📋 **Document policies** - How your team handles no-fix CVEs
4. 🔍 **Regular reviews** - Weekly checks for newly available fixes
5. 🛡️ **Compensating controls** - Required for Critical/High no-fix

**Remember:** "No fix available" doesn't mean "no action required." It means "different actions required" - risk assessment, monitoring, and compensating controls.
