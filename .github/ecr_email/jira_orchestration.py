#!/usr/bin/env python3
"""
ECR Scanner → Jira Lifecycle Automation

This script manages the complete lifecycle of Jira tickets for ECR vulnerability scans.
It implements enterprise-grade automation with the following guarantees:

- Tickets created for all scans (regardless of severity)
- No duplicate active tickets per image
- Severity changes update priority
- Subsequent scans append structured comments
- Tickets auto-close when Critical and High = 0
- Closed tickets are never reopened
- If closed and vulnerabilities reappear → create new ticket
- Multiple ECR repos supported
- Metadata stored in structured format
- System is idempotent
"""

import os
import sys
import json
import logging
import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from jira import JIRA, JIRAError
from jira.exceptions import JIRAError as JIRAException

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class JiraConfig:
    """Jira configuration management with AWS Secrets Manager and environment fallback."""
    
    def __init__(self):
        self.jira_url = os.getenv('JIRA_URL')
        self.jira_username = os.getenv('JIRA_USERNAME')
        self.jira_api_token = os.getenv('JIRA_API_TOKEN')
        self.jira_project = os.getenv('JIRA_PROJECT')
        self.jira_issue_type = os.getenv('JIRA_ISSUE_TYPE', 'Task')
        self.jira_epic_key = os.getenv('JIRA_EPIC_KEY')  # Optional
        
        # Load from AWS Secrets Manager if configured
        aws_secret_name = os.getenv('JIRA_AWS_SECRET_NAME')
        if aws_secret_name:
            self._load_from_aws_secrets(aws_secret_name)
        
        self._validate()
    
    def _load_from_aws_secrets(self, secret_name: str):
        """Load Jira credentials from AWS Secrets Manager."""
        try:
            import boto3
            from botocore.exceptions import ClientError
            
            session = boto3.session.Session()
            client = session.client(service_name='secretsmanager')
            
            try:
                get_secret_value_response = client.get_secret_value(SecretId=secret_name)
            except ClientError as e:
                logger.error(f"Failed to retrieve secret from AWS: {e}")
                return
            
            secret = json.loads(get_secret_value_response['SecretString'])
            
            # Override with secrets if not already set
            self.jira_url = secret.get('jira_url', self.jira_url)
            self.jira_username = secret.get('jira_username', self.jira_username)
            self.jira_api_token = secret.get('jira_api_token', self.jira_api_token)
            self.jira_project = secret.get('jira_project', self.jira_project)
            self.jira_issue_type = secret.get('jira_issue_type', self.jira_issue_type)
            self.jira_epic_key = secret.get('jira_epic_key', self.jira_epic_key)
            
            logger.info(f"Successfully loaded Jira credentials from AWS Secrets Manager: {secret_name}")
        
        except ImportError:
            logger.warning("boto3 not installed. Skipping AWS Secrets Manager integration.")
        except Exception as e:
            logger.error(f"Unexpected error loading from AWS Secrets Manager: {e}")
    
    def _validate(self):
        """Validate required configuration."""
        if not all([self.jira_url, self.jira_username, self.jira_api_token, self.jira_project]):
            raise ValueError(
                "Missing required Jira configuration. Set environment variables: "
                "JIRA_URL, JIRA_USERNAME, JIRA_API_TOKEN, JIRA_PROJECT"
            )
        
        # Normalize URL (remove trailing slash)
        self.jira_url = self.jira_url.rstrip('/')
        
        logger.info(f"Jira configuration validated: {self.jira_url} / {self.jira_project}")


class JiraClient:
    """Jira API client using official Jira Python SDK."""
    
    def __init__(self, config: JiraConfig):
        self.config = config
        
        # Initialize Jira client with basic auth
        try:
            self.client = JIRA(
                server=config.jira_url,
                basic_auth=(config.jira_username, config.jira_api_token),
                options={
                    'verify': True,
                    'max_retries': 3,
                    'timeout': 30
                }
            )
            logger.info(f"Successfully connected to Jira: {config.jira_url}")
        except JIRAError as e:
            logger.error(f"Failed to connect to Jira: {e}")
            raise
    
    def search_issues(self, jql: str, fields: List[str] = None) -> List:
        """Search for issues using JQL."""
        if fields is None:
            fields = ['summary', 'status', 'priority', 'description', 'comment']
        
        try:
            issues = self.client.search_issues(
                jql_str=jql,
                fields=','.join(fields),
                maxResults=100
            )
            return issues
        except JIRAError as e:
            logger.error(f"Failed to search issues: {e}")
            raise
    
    def get_issue(self, issue_key: str):
        """Get issue details."""
        try:
            return self.client.issue(issue_key)
        except JIRAError as e:
            logger.error(f"Failed to get issue {issue_key}: {e}")
            raise
    
    def create_issue(self, fields: Dict):
        """Create a new issue."""
        try:
            issue = self.client.create_issue(fields=fields)
            return issue
        except JIRAError as e:
            logger.error(f"Failed to create issue: {e}")
            raise
    
    def add_comment(self, issue_key: str, comment_body: str):
        """Add comment to issue."""
        try:
            comment = self.client.add_comment(issue_key, comment_body)
            return comment
        except JIRAError as e:
            logger.error(f"Failed to add comment to {issue_key}: {e}")
            raise
    
    def update_issue(self, issue_key: str, fields: Dict) -> None:
        """Update issue fields."""
        try:
            issue = self.client.issue(issue_key)
            issue.update(fields=fields)
        except JIRAError as e:
            logger.error(f"Failed to update issue {issue_key}: {e}")
            raise
    
    def get_transitions(self, issue_key: str) -> List[Dict]:
        """Get available transitions for an issue."""
        try:
            transitions = self.client.transitions(issue_key)
            return transitions
        except JIRAError as e:
            logger.error(f"Failed to get transitions for {issue_key}: {e}")
            raise
    
    def transition_issue(self, issue_key: str, transition_id: str) -> None:
        """Transition issue to new status."""
        try:
            self.client.transition_issue(issue_key, transition_id)
        except JIRAError as e:
            logger.error(f"Failed to transition issue {issue_key}: {e}")
            raise


class MetadataExtractor:
    """Extract and parse metadata from Jira ticket descriptions and comments."""
    
    METADATA_PATTERN = re.compile(
        r'<!--\s*scan-meta:\s*(\{.*?\})\s*-->',
        re.DOTALL
    )
    
    @classmethod
    def extract_from_text(cls, text: str) -> Optional[Dict]:
        """Extract metadata from HTML comment."""
        if not text:
            return None
        
        match = cls.METADATA_PATTERN.search(text)
        if not match:
            return None
        
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse metadata JSON: {e}")
            return None
    
    @classmethod
    def extract_latest_from_issue(cls, issue) -> Optional[Dict]:
        """Extract latest metadata from issue description and comments."""
        all_metadata = []
        
        # Extract from description
        description = getattr(issue.fields, 'description', '')
        if description:
            desc_meta = cls.extract_from_text(description)
            if desc_meta:
                all_metadata.append(desc_meta)
        
        # Extract from comments
        try:
            comments = issue.fields.comment.comments
            for comment in comments:
                comment_body = comment.body
                comment_meta = cls.extract_from_text(comment_body)
                if comment_meta:
                    all_metadata.append(comment_meta)
        except AttributeError:
            # No comments field
            pass
        
        # Return latest (most recent scan)
        if not all_metadata:
            return None
        
        # Sort by scan_time and return most recent
        try:
            sorted_meta = sorted(
                all_metadata,
                key=lambda x: x.get('scan_time', ''),
                reverse=True
            )
            return sorted_meta[0]
        except Exception as e:
            logger.warning(f"Failed to sort metadata: {e}")
            return all_metadata[-1]  # Return last one
    
    @staticmethod
    def format_metadata(image: str, scan_time: str, critical: int, high: int, medium: int, low: int) -> str:
        """Format metadata as HTML comment."""
        metadata = {
            'image': image,
            'scan_time': scan_time,
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low
        }
        return f"\n\n<!-- scan-meta:\n{json.dumps(metadata, indent=2)}\n-->"


class JiraOrchestrator:
    """Main orchestration logic for Jira ticket lifecycle management."""
    
    # Default labels
    DEFAULT_LABELS = ['ecr-scan', 'security', 'container']
    
    # Priority mapping
    PRIORITY_P0 = 'P0'
    PRIORITY_P1 = 'P1'
    
    def __init__(self, client: JiraClient, config: JiraConfig):
        self.client = client
        self.config = config
    
    def run(
        self,
        image_name: str,
        scan_time: str,
        critical_count: int,
        high_count: int,
        medium_count: int,
        low_count: int,
        github_security_link: str
    ) -> None:
        """
        Main entry point for Jira orchestration.
        
        This method handles the complete lifecycle:
        1. Search for existing open ticket
        2. Create new ticket if none exists
        3. Update existing ticket if found
        4. Handle priority changes
        5. Auto-close if Critical + High = 0
        """
        logger.info(f"Starting Jira orchestration for image: {image_name}")
        logger.info(f"Severity counts - Critical: {critical_count}, High: {high_count}, Medium: {medium_count}, Low: {low_count}")
        
        # Search for existing open ticket
        ticket_summary = f"ecr scanner findings - {image_name}"
        existing_ticket = self.search_ticket(ticket_summary)
        
        if existing_ticket:
            logger.info(f"Found existing open ticket: {existing_ticket['key']}")
            self.update_ticket(
                existing_ticket,
                image_name,
                scan_time,
                critical_count,
                high_count,
                medium_count,
                low_count,
                github_security_link
            )
        else:
            logger.info("No existing open ticket found. Creating new ticket.")
            self.create_ticket(
                image_name,
                scan_time,
                critical_count,
                high_count,
                medium_count,
                low_count,
                github_security_link
            )
        
        logger.info("Jira orchestration completed successfully")
    
    def search_ticket(self, summary: str):
        """
        Search for existing open ticket by exact summary match.
        
        Returns None if:
        - No ticket exists
        - Ticket exists but is closed (StatusCategory = Done)
        """
        # Escape JQL special characters in summary
        escaped_summary = summary.replace('"', '\\"')
        
        jql = (
            f'project = "{self.config.jira_project}" '
            f'AND summary ~ "\"{escaped_summary}\"" '
            f'AND statusCategory != Done '
            f'ORDER BY created DESC'
        )
        
        logger.info(f"Searching with JQL: {jql}")
        
        try:
            issues = self.client.search_issues(jql)
            
            if not issues:
                return None
            
            # Find exact match (JQL ~ is fuzzy, we need exact)
            for issue in issues:
                issue_summary = issue.fields.summary
                if issue_summary == summary:
                    return issue
            
            return None
        
        except Exception as e:
            logger.error(f"Failed to search for ticket: {e}")
            raise
    
    def create_ticket(
        self,
        image_name: str,
        scan_time: str,
        critical_count: int,
        high_count: int,
        medium_count: int,
        low_count: int,
        github_security_link: str
    ):
        """Create a new Jira ticket for the scan results."""
        logger.info(f"Creating new ticket for image: {image_name}")
        
        # Determine priority
        priority = self.PRIORITY_P0 if critical_count > 0 else self.PRIORITY_P1
        
        # Format description
        description = self._format_initial_description(
            image_name,
            scan_time,
            critical_count,
            high_count,
            medium_count,
            low_count,
            github_security_link
        )
        
        # Build fields
        fields = {
            'project': {'key': self.config.jira_project},
            'summary': f"ecr scanner findings - {image_name}",
            'description': description,
            'issuetype': {'name': self.config.jira_issue_type},
            'priority': {'name': priority},
            'labels': self.DEFAULT_LABELS
        }
        
        # Add epic link if configured
        if self.config.jira_epic_key:
            # Try common epic link field names
            # Note: Field name varies by Jira configuration
            fields['parent'] = {'key': self.config.jira_epic_key}
        
        try:
            issue = self.client.create_issue(fields)
            issue_key = issue.key
            logger.info(f"Successfully created ticket: {issue_key}")
            return issue
        
        except Exception as e:
            logger.error(f"Failed to create ticket: {e}")
            raise
    
    def update_ticket(
        self,
        ticket,
        image_name: str,
        scan_time: str,
        critical_count: int,
        high_count: int,
        medium_count: int,
        low_count: int,
        github_security_link: str
    ) -> None:
        """Update existing ticket with new scan results."""
        ticket_key = ticket.key
        logger.info(f"Updating ticket: {ticket_key}")
        
        # Extract latest metadata
        previous_meta = MetadataExtractor.extract_latest_from_issue(ticket)
        
        # Determine if we need to update priority
        current_priority = ticket.fields.priority.name if hasattr(ticket.fields, 'priority') and ticket.fields.priority else ''
        new_priority = self.PRIORITY_P0 if critical_count > 0 else self.PRIORITY_P1
        
        if current_priority != new_priority:
            logger.info(f"Updating priority: {current_priority} → {new_priority}")
            self.update_priority(ticket_key, new_priority)
        
        # Check for auto-close condition
        if critical_count == 0 and high_count == 0:
            logger.info("Critical and High vulnerabilities are zero. Auto-closing ticket.")
            self.close_ticket(ticket_key, scan_time)
            return  # Stop processing after auto-close
        
        # Check if this is first update (no metadata in comments yet)
        is_first_update = previous_meta is None or self._is_description_only_metadata(ticket, previous_meta)
        
        if is_first_update:
            logger.info("First update detected. Adding note to description.")
            self._append_description_note(ticket_key)
        
        # Add rescan comment
        self._add_rescan_comment(
            ticket_key,
            scan_time,
            critical_count,
            high_count,
            medium_count,
            low_count,
            github_security_link,
            previous_meta
        )
    
    def update_priority(self, ticket_key: str, priority: str) -> None:
        """Update ticket priority."""
        try:
            fields = {'priority': {'name': priority}}
            self.client.update_issue(ticket_key, fields)
            logger.info(f"Successfully updated priority to: {priority}")
        except Exception as e:
            logger.error(f"Failed to update priority: {e}")
            # Non-fatal error
    
    def close_ticket(self, ticket_key: str, scan_time: str) -> None:
        """Auto-close ticket when Critical and High vulnerabilities are zero."""
        logger.info(f"Auto-closing ticket: {ticket_key}")
        
        # Add closing comment
        comment = (
            f"✅ Critical and High vulnerabilities are now zero.\n\n"
            f"Scan Time: {scan_time}\n\n"
            f"This ticket is being auto-closed."
        )
        
        try:
            self.client.add_comment(ticket_key, comment)
        except Exception as e:
            logger.warning(f"Failed to add closing comment: {e}")
        
        # Find and execute transition
        try:
            transitions = self.client.get_transitions(ticket_key)
            
            # Look for common closing transitions
            close_transition = None
            for transition in transitions:
                name = transition.get('name', '').lower()
                if any(keyword in name for keyword in ['done', 'resolved', 'close']):
                    close_transition = transition
                    break
            
            if close_transition:
                transition_id = close_transition['id']
                transition_name = close_transition['name']
                logger.info(f"Executing transition: {transition_name} (ID: {transition_id})")
                self.client.transition_issue(ticket_key, transition_id)
                logger.info(f"Successfully closed ticket: {ticket_key}")
            else:
                logger.warning(f"No suitable closing transition found for {ticket_key}")
                logger.warning(f"Available transitions: {[t.get('name') for t in transitions]}")
        
        except Exception as e:
            logger.error(f"Failed to close ticket: {e}")
            # Non-fatal error
    
    def _format_initial_description(
        self,
        image_name: str,
        scan_time: str,
        critical_count: int,
        high_count: int,
        medium_count: int,
        low_count: int,
        github_security_link: str
    ) -> str:
        """Format initial ticket description."""
        description = (
            f"🔍 Initial ECR Scan Results\n\n"
            f"Image: {image_name}\n"
            f"Scan Time: {scan_time}\n\n"
            f"Severity Split:\n"
            f"🔴 Critical: {critical_count}\n"
            f"🟠 High: {high_count}\n"
            f"🟡 Medium: {medium_count}\n"
            f"🔵 Low: {low_count}\n\n"
            f"GitHub Security View:\n{github_security_link}"
        )
        
        # Append metadata
        metadata = MetadataExtractor.format_metadata(
            image_name,
            scan_time,
            critical_count,
            high_count,
            medium_count,
            low_count
        )
        
        return description + metadata
    
    def _append_description_note(self, ticket_key: str) -> None:
        """Append note to description on first update."""
        try:
            issue = self.client.get_issue(ticket_key)
            current_desc = getattr(issue.fields, 'description', '')
            
            # Check if note already exists
            if '⚠️ NOTE:' in current_desc:
                logger.info("Description note already exists. Skipping.")
                return
            
            # Append note
            note = (
                "\n\n⚠️ NOTE:\n"
                "The vulnerability count above reflects the initial scan.\n"
                "Refer to comments for the most recent scan results."
            )
            
            new_description = current_desc + note
            
            fields = {'description': new_description}
            self.client.update_issue(ticket_key, fields)
            logger.info("Successfully appended description note")
        
        except Exception as e:
            logger.error(f"Failed to append description note: {e}")
            # Non-fatal error
    
    def _add_rescan_comment(
        self,
        ticket_key: str,
        scan_time: str,
        critical_count: int,
        high_count: int,
        medium_count: int,
        low_count: int,
        github_security_link: str,
        previous_meta: Optional[Dict]
    ) -> None:
        """Add rescan comment with comparison to previous scan."""
        # Build change comparison
        if previous_meta:
            prev_critical = previous_meta.get('critical', 0)
            prev_high = previous_meta.get('high', 0)
            prev_medium = previous_meta.get('medium', 0)
            prev_low = previous_meta.get('low', 0)
            
            change_text = (
                f"Change From Previous:\n"
                f"Critical: {prev_critical} → {critical_count}\n"
                f"High: {prev_high} → {high_count}\n"
                f"Medium: {prev_medium} → {medium_count}\n"
                f"Low: {prev_low} → {low_count}\n\n"
            )
        else:
            change_text = ""
        
        comment = (
            f"🔄 ECR Image Rescan\n\n"
            f"Scan Time: {scan_time}\n\n"
            f"Severity Split:\n"
            f"🔴 Critical: {critical_count}\n"
            f"🟠 High: {high_count}\n"
            f"🟡 Medium: {medium_count}\n"
            f"🔵 Low: {low_count}\n\n"
            f"{change_text}"
            f"GitHub Security View:\n{github_security_link}"
        )
        
        # Append metadata
        metadata = MetadataExtractor.format_metadata(
            previous_meta.get('image', '') if previous_meta else '',
            scan_time,
            critical_count,
            high_count,
            medium_count,
            low_count
        )
        
        comment += metadata
        
        try:
            self.client.add_comment(ticket_key, comment)
            logger.info("Successfully added rescan comment")
        except Exception as e:
            logger.error(f"Failed to add rescan comment: {e}")
            raise
    
    @staticmethod
    def _is_description_only_metadata(ticket, metadata: Dict) -> bool:
        """Check if metadata only exists in description (not in comments)."""
        try:
            comments = ticket.fields.comment.comments
            for comment in comments:
                comment_body = comment.body
                if 'scan-meta:' in comment_body:
                    return False  # Metadata found in comment
        except AttributeError:
            # No comments field
            pass
        
        return True  # Metadata only in description


def main():
    """Main entry point."""
    # Parse command line arguments
    if len(sys.argv) < 8:
        print("Usage: python jira_orchestration.py <image_name> <scan_time> <critical> <high> <medium> <low> <github_link>")
        sys.exit(1)
    
    image_name = sys.argv[1]
    scan_time = sys.argv[2]
    critical_count = int(sys.argv[3])
    high_count = int(sys.argv[4])
    medium_count = int(sys.argv[5])
    low_count = int(sys.argv[6])
    github_security_link = sys.argv[7]
    
    try:
        # Initialize configuration
        config = JiraConfig()
        
        # Initialize client
        client = JiraClient(config)
        
        # Initialize orchestrator
        orchestrator = JiraOrchestrator(client, config)
        
        # Run orchestration
        orchestrator.run(
            image_name=image_name,
            scan_time=scan_time,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            github_security_link=github_security_link
        )
        
        logger.info("✅ Jira orchestration completed successfully")
        sys.exit(0)
    
    except Exception as e:
        logger.error(f"❌ Jira orchestration failed: {e}", exc_info=True)
        
        # Check if we should fail the workflow
        fail_on_error = os.getenv('JIRA_FAIL_ON_ERROR', 'false').lower() == 'true'
        
        if fail_on_error:
            sys.exit(1)
        else:
            logger.warning("Continuing despite Jira error (JIRA_FAIL_ON_ERROR=false)")
            sys.exit(0)


if __name__ == '__main__':
    main()
