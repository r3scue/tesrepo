#!/usr/bin/env python3
"""
Container Vulnerability Enrichment Engine for Python Dependencies

This script enriches SARIF vulnerability reports by analyzing Python package
dependency chains using CycloneDX SBOM data.

Input files:
- trivy-report.json: Trivy vulnerability scan results
- sbom.json: CycloneDX SBOM from the same image
- trivy-results-updated.sarif: SARIF file to enrich

Output:
- Overwrites trivy-results-updated.sarif with enriched dependency analysis
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict


class DependencyGraph:
    """Build and query a dependency graph from CycloneDX SBOM."""
    
    def __init__(self, sbom_data: dict):
        self.components: Dict[str, dict] = {}
        self.children_to_parents: Dict[str, Set[str]] = defaultdict(set)
        self.parents_to_children: Dict[str, Set[str]] = defaultdict(set)
        self._build_graph(sbom_data)
    
    def _normalize_purl(self, purl: str) -> str:
        """Normalize package URL for consistent matching."""
        if not purl:
            return ""
        # Remove version qualifiers for matching
        # e.g., pkg:pypi/requests@2.28.0 -> pkg:pypi/requests
        if '@' in purl:
            return purl.split('@')[0]
        return purl
    
    def _get_package_name_from_purl(self, purl: str) -> Optional[str]:
        """Extract package name from purl."""
        if not purl or not purl.startswith('pkg:pypi/'):
            return None
        # pkg:pypi/package-name@version -> package-name
        name_part = purl.replace('pkg:pypi/', '').split('@')[0]
        return name_part
    
    def _build_graph(self, sbom_data: dict):
        """Build dependency graph from CycloneDX SBOM."""
        # Index components by purl and bom-ref
        components = sbom_data.get('components', [])
        bom_ref_to_purl = {}
        
        for component in components:
            purl = component.get('purl', '')
            bom_ref = component.get('bom-ref', '')
            
            if purl:
                normalized = self._normalize_purl(purl)
                self.components[normalized] = component
                if bom_ref:
                    bom_ref_to_purl[bom_ref] = normalized
        
        # Build parent-child relationships
        dependencies = sbom_data.get('dependencies', [])
        
        for dep_entry in dependencies:
            parent_ref = dep_entry.get('ref', '')
            child_refs = dep_entry.get('dependsOn', [])
            
            parent_purl = bom_ref_to_purl.get(parent_ref)
            if not parent_purl:
                continue
            
            for child_ref in child_refs:
                child_purl = bom_ref_to_purl.get(child_ref)
                if not child_purl:
                    continue
                
                self.children_to_parents[child_purl].add(parent_purl)
                self.parents_to_children[parent_purl].add(child_purl)
    
    def find_package_by_name(self, package_name: str) -> Optional[str]:
        """Find package purl by name (case-insensitive, handles normalization)."""
        target = package_name.lower().replace('_', '-')
        
        for purl in self.components.keys():
            pkg_name = self._get_package_name_from_purl(purl)
            if pkg_name and pkg_name.lower().replace('_', '-') == target:
                return purl
        return None
    
    def get_root_dependencies(self, package_purl: str) -> List[List[str]]:
        """
        Find all root dependencies that introduce this package.
        Returns list of dependency paths from root to package.
        """
        paths = []
        visited = set()
        
        def dfs(current: str, path: List[str]):
            """DFS to find all paths to root dependencies."""
            if current in visited and current in path:
                # Circular dependency detected, stop
                return
            
            parents = self.children_to_parents.get(current, set())
            
            if not parents:
                # Root dependency found
                paths.append(list(reversed(path)))
                return
            
            visited.add(current)
            for parent in sorted(parents):  # Sort for determinism
                dfs(parent, path + [parent])
            visited.discard(current)
        
        dfs(package_purl, [package_purl])
        
        # Deduplicate and sort paths
        unique_paths = []
        seen = set()
        for path in sorted(paths, key=len):  # Prefer shorter paths
            path_key = tuple(path)
            if path_key not in seen:
                unique_paths.append(path)
                seen.add(path_key)
        
        return unique_paths
    
    def is_direct_dependency(self, package_purl: str) -> bool:
        """Check if package is a direct (root) dependency."""
        return len(self.children_to_parents.get(package_purl, set())) == 0


class VulnerabilityEnricher:
    """Enrich SARIF vulnerability reports with Python dependency analysis."""
    
    def __init__(self, trivy_report_path: str, sbom_path: str, sarif_path: str):
        self.trivy_report_path = Path(trivy_report_path)
        self.sbom_path = Path(sbom_path)
        self.sarif_path = Path(sarif_path)
        
        self.trivy_data = None
        self.sbom_data = None
        self.sarif_data = None
        self.dependency_graph = None
    
    def load_data(self) -> bool:
        """Load all required JSON files."""
        try:
            with open(self.trivy_report_path) as f:
                self.trivy_data = json.load(f)
            
            with open(self.sbom_path) as f:
                self.sbom_data = json.load(f)
            
            with open(self.sarif_path) as f:
                self.sarif_data = json.load(f)
            
            self.dependency_graph = DependencyGraph(self.sbom_data)
            return True
            
        except FileNotFoundError as e:
            print(f"❌ Error: Required file not found: {e}", file=sys.stderr)
            return False
        except json.JSONDecodeError as e:
            print(f"❌ Error: Invalid JSON: {e}", file=sys.stderr)
            return False
    
    def get_python_vulnerabilities(self) -> Dict[str, List[dict]]:
        """
        Extract Python vulnerabilities from Trivy report.
        Returns dict mapping package names to vulnerability details.
        """
        python_vulns = defaultdict(list)
        
        for result in self.trivy_data.get('Results', []):
            result_type = result.get('Type', '')
            
            # Only process Python library vulnerabilities
            if result_type != 'python-pkg':
                continue
            
            for vuln in result.get('Vulnerabilities', []):
                pkg_name = vuln.get('PkgName', '')
                if pkg_name:
                    python_vulns[pkg_name].append(vuln)
        
        return python_vulns
    
    def analyze_dependency(self, package_name: str) -> dict:
        """
        Analyze dependency chain for a vulnerable package.
        
        Returns:
        {
            'is_direct': bool,
            'root_paths': List[List[str]],  # List of dependency paths
            'status': 'resolved' | 'unresolved'
        }
        """
        package_purl = self.dependency_graph.find_package_by_name(package_name)
        
        if not package_purl:
            return {
                'is_direct': False,
                'root_paths': [],
                'status': 'unresolved'
            }
        
        is_direct = self.dependency_graph.is_direct_dependency(package_purl)
        root_paths = self.dependency_graph.get_root_dependencies(package_purl)
        
        return {
            'is_direct': is_direct,
            'root_paths': root_paths,
            'status': 'resolved'
        }
    
    def format_dependency_path(self, path_purls: List[str]) -> str:
        """Format dependency path for display."""
        names = []
        for purl in path_purls:
            name = self.dependency_graph._get_package_name_from_purl(purl)
            if name:
                names.append(name)
        return ' → '.join(names)
    
    def enrich_sarif(self) -> bool:
        """Enrich SARIF file with Python dependency analysis."""
        python_vulns = self.get_python_vulnerabilities()
        
        if not python_vulns:
            print("ℹ️  No Python vulnerabilities found. SARIF unchanged.")
            return True
        
        print(f"🔍 Found {sum(len(v) for v in python_vulns.values())} Python vulnerabilities across {len(python_vulns)} packages")
        
        # Build a mapping of CVE ID -> package names for quick lookup
        cve_to_packages = defaultdict(set)
        for pkg_name, vulns in python_vulns.items():
            for vuln in vulns:
                vuln_id = vuln.get('VulnerabilityID', '')
                if vuln_id:
                    cve_to_packages[vuln_id].add(pkg_name)
        
        enriched_count = 0
        unresolved_count = 0
        
        # Process each SARIF run
        for run in self.sarif_data.get('runs', []):
            results = run.get('results', [])
            
            for result in results:
                # Try multiple methods to extract package name
                pkg_name = None
                
                # Method 1: Use ruleId (CVE ID) to lookup package
                rule_id = result.get('ruleId', '')
                if rule_id and rule_id in cve_to_packages:
                    # Get all packages affected by this CVE
                    affected_packages = cve_to_packages[rule_id]
                    if len(affected_packages) == 1:
                        pkg_name = list(affected_packages)[0]
                    else:
                        # Multiple packages, try to disambiguate from message
                        pkg_name = self._extract_package_name_from_result(result)
                        if pkg_name and pkg_name in affected_packages:
                            # Use the extracted name if it matches
                            pass
                        else:
                            # Fallback to first package
                            pkg_name = sorted(list(affected_packages))[0]  # Sort for determinism
                else:
                    # Method 2: Extract from message text
                    pkg_name = self._extract_package_name_from_result(result)
                
                if not pkg_name or pkg_name not in python_vulns:
                    continue
                
                # Analyze dependency
                analysis = self.analyze_dependency(pkg_name)
                
                # Build enrichment text
                enrichment = self._build_enrichment_text(pkg_name, analysis)
                
                # Append to message
                current_message = result['message']['text']
                result['message']['text'] = f"{current_message}\n\n{enrichment}"
                
                if analysis['status'] == 'resolved':
                    enriched_count += 1
                else:
                    unresolved_count += 1
        
        print(f"✅ Enriched {enriched_count} Python vulnerabilities")
        if unresolved_count > 0:
            print(f"⚠️  {unresolved_count} vulnerabilities could not be mapped to SBOM")
        
        return True
    
    def _extract_package_name_from_result(self, result: dict) -> Optional[str]:
        """Extract package name from SARIF result."""
        # Trivy SARIF format stores package info in multiple places
        
        message = result.get('message', {}).get('text', '')
        
        # Try to extract package name from various patterns
        # Pattern 1: Look for lines like "Package: xyz" or "PkgName: xyz"
        lines = message.split('\n')
        for line in lines:
            if line.strip().startswith('Package:'):
                return line.split(':', 1)[1].strip()
            if line.strip().startswith('PkgName:'):
                return line.split(':', 1)[1].strip()
        
        # Pattern 2: Look for purl format in message
        if 'pkg:pypi/' in message:
            import re
            match = re.search(r'pkg:pypi/([a-zA-Z0-9._-]+)', message)
            if match:
                return match.group(1)
        
        # Pattern 3: Parse the original Trivy message after the enrichment header
        # Look for common vulnerability message patterns
        # E.g., "python-package 1.2.3 is affected by CVE-..."
        import re
        
        # After the "Container Path:" line, look for package name in next lines
        # Container Path often contains: /path/to/package_name/
        for i, line in enumerate(lines):
            if 'Container Path:' in line:
                # Extract from path like "/usr/local/lib/python3.9/site-packages/urllib3"
                path = line.split(':', 1)[1].strip() if ':' in line else ''
                if '/site-packages/' in path:
                    pkg = path.split('/site-packages/')[-1].strip('/')
                    # Remove any trailing path components
                    pkg = pkg.split('/')[0]
                    if pkg:
                        return pkg
                
                # Also check the next non-empty line after Container Path
                if i + 1 < len(lines):
                    next_lines = lines[i+1:]
                    for next_line in next_lines:
                        if not next_line.strip():
                            continue
                        # Pattern: "package-name version has CVE-..."
                        match = re.match(r'^([a-zA-Z0-9._-]+)\s+[\d.]+', next_line.strip())
                        if match:
                            return match.group(1)
                        # Pattern: "Package package-name"
                        match = re.search(r'[Pp]ackage\s+([a-zA-Z0-9._-]+)', next_line)
                        if match:
                            return match.group(1)
                        break
                break
        
        return None
    
    def _build_enrichment_text(self, package_name: str, analysis: dict) -> str:
        """Build enrichment text for SARIF message."""
        if analysis['status'] == 'unresolved':
            return (
                "─────────────────────────────────\n"
                "📦 Dependency Analysis:\n"
                f"   Package: {package_name}\n"
                "   Status: Could not resolve dependency chain\n"
                "   Note: Package not found in SBOM or dependency graph incomplete"
            )
        
        text_parts = [
            "─────────────────────────────────",
            "📦 Python Dependency Analysis:"
        ]
        
        if analysis['is_direct']:
            text_parts.append(f"   • Direct dependency: ✓ (root package)")
            text_parts.append(f"   • Package: {package_name}")
        else:
            text_parts.append(f"   • Direct dependency: ✗ (transitive)")
            text_parts.append(f"   • Vulnerable package: {package_name}")
            
            root_paths = analysis['root_paths']
            if root_paths:
                text_parts.append("   • Introduced by:")
                
                # Show up to 5 paths to avoid overwhelming the message
                for i, path in enumerate(root_paths[:5]):
                    formatted_path = self.format_dependency_path(path)
                    text_parts.append(f"      {i+1}. {formatted_path}")
                
                if len(root_paths) > 5:
                    text_parts.append(f"      ... and {len(root_paths) - 5} more path(s)")
            else:
                text_parts.append("   • Introduced by: Could not determine root package")
        
        return '\n'.join(text_parts)
    
    def save_sarif(self) -> bool:
        """Save enriched SARIF file."""
        try:
            with open(self.sarif_path, 'w') as f:
                json.dump(self.sarif_data, f, indent=2)
            print(f"💾 Saved enriched SARIF to {self.sarif_path}")
            return True
        except Exception as e:
            print(f"❌ Error saving SARIF: {e}", file=sys.stderr)
            return False
    
    def validate_sarif(self) -> bool:
        """Basic SARIF validation."""
        try:
            # Check basic structure
            if 'runs' not in self.sarif_data:
                print("❌ Invalid SARIF: missing 'runs'", file=sys.stderr)
                return False
            
            for run in self.sarif_data['runs']:
                if 'results' not in run:
                    print("❌ Invalid SARIF: missing 'results' in run", file=sys.stderr)
                    return False
                
                if 'tool' not in run or 'driver' not in run['tool']:
                    print("❌ Invalid SARIF: missing 'tool.driver'", file=sys.stderr)
                    return False
            
            print("✅ SARIF validation passed")
            return True
            
        except Exception as e:
            print(f"❌ SARIF validation error: {e}", file=sys.stderr)
            return False


def main():
    """Main entry point."""
    if len(sys.argv) != 4:
        print("Usage: enrich_python_vulnerabilities.py <trivy-report.json> <sbom.json> <sarif-file.sarif>")
        sys.exit(1)
    
    trivy_report = sys.argv[1]
    sbom_file = sys.argv[2]
    sarif_file = sys.argv[3]
    
    print("🚀 Container Vulnerability Enrichment Engine")
    print(f"   Trivy Report: {trivy_report}")
    print(f"   SBOM: {sbom_file}")
    print(f"   SARIF: {sarif_file}")
    print()
    
    enricher = VulnerabilityEnricher(trivy_report, sbom_file, sarif_file)
    
    # Load data
    if not enricher.load_data():
        sys.exit(1)
    
    # Enrich SARIF
    if not enricher.enrich_sarif():
        sys.exit(1)
    
    # Validate
    if not enricher.validate_sarif():
        sys.exit(1)
    
    # Save
    if not enricher.save_sarif():
        sys.exit(1)
    
    print()
    print("✨ Enrichment complete!")


if __name__ == '__main__':
    main()
