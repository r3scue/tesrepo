#!/usr/bin/env python3
"""
Container Vulnerability Enrichment Engine for Multi-Ecosystem Dependencies

This script enriches SARIF vulnerability reports by analyzing package
dependency chains using CycloneDX SBOM data.

Supports: Python (pip), Node.js (npm), and other ecosystems

Input files:
- trivy-report.json: Trivy vulnerability scan results
- sbom.json: CycloneDX SBOM from the same image
- trivy-results-updated.sarif: SARIF file to enrich

Output:
- Overwrites trivy-results-updated.sarif with enriched dependency analysis
"""

import json
import sys
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict
from urllib.parse import unquote


class DependencyGraph:
    """Build and query a dependency graph from CycloneDX SBOM."""
    
    def __init__(self, sbom_data: dict):
        self.components_by_purl: Dict[str, List[dict]] = defaultdict(list)  # Changed to list for duplicate purls
        self.name_index: Dict[str, List[str]] = defaultdict(list)
        self.parents: Dict[str, Set[str]] = defaultdict(set)  # purl/bom-ref → parents
        self.children: Dict[str, Set[str]] = defaultdict(set)  # purl/bom-ref → children
        self.bom_ref_to_purl: Dict[str, str] = {}  # UUID → canonical purl
        self.purl_to_bom_refs: Dict[str, List[str]] = defaultdict(list)  # purl → all bom-refs
        self._build_graph(sbom_data)
    
    def _get_package_name_from_purl(self, purl: str) -> Optional[str]:
        """Extract package name from purl for any ecosystem."""
        if not purl:
            return None
        
        # Format: pkg:ECOSYSTEM/package-name@version
        match = re.match(r'pkg:([^/]+)/([^@]+)', purl)
        if match:
            # Decode URL encoding (e.g., %40 → @)
            package_name = unquote(match.group(2))
            return package_name
        
        return None
    
    def _get_version_from_purl(self, purl: str) -> Optional[str]:
        """Extract version from purl."""
        if not purl or '@' not in purl:
            return None
        
        # Format: pkg:ECOSYSTEM/package-name@version
        parts = purl.split('@')
        if len(parts) >= 2:
            return parts[-1]
        
        return None
    
    def _get_ecosystem_from_purl(self, purl: str) -> Optional[str]:
        """Extract ecosystem from purl (pypi, npm, etc.)."""
        if not purl:
            return None
        
        match = re.match(r'pkg:([^/]+)/', purl)
        if match:
            return match.group(1).lower()
        
        return None
    
    def _build_graph(self, sbom_data: dict):
        """Build dependency graph from CycloneDX SBOM with support for duplicate purls."""
        # Index components by purl and bom-ref
        # Handle cases where multiple components have the same purl (different locations in container)
        components = sbom_data.get('components', [])
        
        for component in components:
            purl = component.get('purl', '')
            bom_ref = component.get('bom-ref', '')
            
            if purl:
                # Store ALL components with this purl (there may be duplicates at different paths)
                self.components_by_purl[purl].append(component)
                
                # Build name index for reverse lookups
                pkg_name = self._get_package_name_from_purl(purl)
                if pkg_name and purl not in self.name_index[pkg_name.lower()]:
                    self.name_index[pkg_name.lower()].append(purl)
                
                if bom_ref:
                    # Map bom-ref (UUID or purl) to canonical purl
                    self.bom_ref_to_purl[bom_ref] = purl
                    self.purl_to_bom_refs[purl].append(bom_ref)
        
        # Build parent-child relationships using bom-refs as keys
        # This allows us to track relationships for duplicate purls separately
        dependencies = sbom_data.get('dependencies', [])
        
        for dep_entry in dependencies:
            parent_ref = dep_entry.get('ref', '')
            child_refs = dep_entry.get('dependsOn', [])
            
            if not parent_ref:
                continue
            
            for child_ref in child_refs:
                if not child_ref:
                    continue
                
                # Store relationships using bom-refs (which are unique)
                # This preserves separate dependency chains for duplicate purls
                self.parents[child_ref].add(parent_ref)
                self.children[parent_ref].add(child_ref)
        

    
    def get_stats(self) -> dict:
        """Get dependency graph statistics for debugging."""
        total_component_instances = sum(len(instances) for instances in self.components_by_purl.values())
        return {
            'total_components': len(self.components_by_purl),  # Unique purls
            'total_component_instances': total_component_instances,  # Including duplicates
            'packages_with_parents': len([p for p in self.parents if self.parents.get(p)]),
            'packages_without_parents': len([p for p in self.parents if not self.parents.get(p)]) + 
                                       len([p for p in self.components_by_purl if p not in self.parents]),
            'total_dependency_edges': sum(len(parents) for parents in self.parents.values())
        }
    
    def find_exact_purl(self, name: str, version: str, ecosystem: str) -> Optional[str]:
        """
        Find exact package URL matching name, version, and ecosystem.
        Returns the purl if found, None otherwise.
        """
        # Construct expected purl
        expected_purl = f"pkg:{ecosystem}/{name}@{version}"
        
        if expected_purl in self.components_by_purl:
            return expected_purl
        
        # Try case-insensitive search in name index
        normalized_name = name.lower()
        if normalized_name in self.name_index:
            for purl in self.name_index[normalized_name]:
                purl_version = self._get_version_from_purl(purl)
                purl_ecosystem = self._get_ecosystem_from_purl(purl)
                
                if purl_version == version and purl_ecosystem == ecosystem:
                    return purl
        
        return None
    
    def find_package_by_name(self, package_name: str) -> List[str]:
        """
        Find ALL package purls matching the given name (case-insensitive).
        Returns list of purls for all versions of the package.
        """
        normalized_name = package_name.lower().replace('_', '-')
        
        # Direct lookup in name index
        if normalized_name in self.name_index:
            return list(self.name_index[normalized_name])
        
        # Fallback: fuzzy search with normalization
        matches = []
        for indexed_name, purls in self.name_index.items():
            if indexed_name.replace('_', '-') == normalized_name:
                matches.extend(purls)
        
        return matches
    
    def get_root_paths(self, purl: str) -> List[List[str]]:
        """
        Find all paths from root dependencies to the target purl.
        Returns list of paths, where each path is [root, ..., target].
        Handles duplicate purls by finding paths for ALL instances.
        """
        all_paths = []
        
        # Get all bom-refs for this purl (might be multiple instances)
        bom_refs = self.purl_to_bom_refs.get(purl, [])
        
        # If purl is used as direct bom-ref (no UUID), include it
        if not bom_refs and purl in self.parents:
            bom_refs = [purl]
        
        # Find paths for each instance of this purl
        for bom_ref in bom_refs:
            instance_paths = self._get_root_paths_for_ref(bom_ref)
            all_paths.extend(instance_paths)
        
        # Deduplicate and sort by length
        unique_paths = []
        seen = set()
        for path in sorted(all_paths, key=len):
            path_key = tuple(path)
            if path_key not in seen:
                unique_paths.append(path)
                seen.add(path_key)
        
        return unique_paths
    
    def _get_root_paths_for_ref(self, bom_ref: str) -> List[List[str]]:
        """
        Find all paths from root dependencies to the target bom-ref.
        Uses bom-refs for path resolution to handle duplicate purls correctly.
        """
        paths = []
        
        def dfs(current_ref: str, path: List[str]):
            # Check for circular dependency
            if current_ref in path:
                return
            
            # Add current node to path
            current_path = path + [current_ref]
            
            parent_refs = self.parents.get(current_ref, set())
            
            if not parent_refs:
                # Root dependency found - convert bom-refs to purls for display
                purl_path = []
                for ref in current_path:
                    # Check if ref is already a purl or needs conversion
                    if ref.startswith('pkg:'):
                        purl_path.append(ref)
                    else:
                        # It's a UUID, convert to purl
                        purl = self.bom_ref_to_purl.get(ref, ref)
                        purl_path.append(purl)
                
                # Reverse to show root → ... → target
                paths.append(list(reversed(purl_path)))
                return
            
            # Recurse to parents
            for parent_ref in sorted(parent_refs):  # Sort for determinism
                dfs(parent_ref, current_path)
        
        # Start DFS with empty path
        dfs(bom_ref, [])
        
        return paths
    
    def is_direct_dependency(self, purl: str) -> bool:
        """
        Check if package is a direct (root) dependency.
        A purl is direct ONLY if ALL of its instances have no parents.
        If any instance has parents (transitive), we want to show those paths.
        """
        # Check all bom-refs for this purl
        bom_refs = self.purl_to_bom_refs.get(purl, [])
        
        # If purl is used as direct bom-ref, check it too
        if not bom_refs and purl in self.parents:
            bom_refs = [purl]
        
        if not bom_refs:
            # No instances found, assume direct
            return True
        
        # Direct ONLY if ALL instances have no parents
        # If any instance has parents, we have transitive paths to show
        for bom_ref in bom_refs:
            if len(self.parents.get(bom_ref, set())) > 0:
                # At least one instance has parents -> not purely direct
                return False
        
        # All instances have no parents
        return True


class VulnerabilityEnricher:
    """Enrich SARIF vulnerability reports with dependency analysis."""
    
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
            
            # Log dependency graph statistics
            stats = self.dependency_graph.get_stats()
            print(f"📊 Dependency Graph Statistics:")
            print(f"   - Total packages in SBOM: {stats['total_components']}")
            print(f"   - Packages with dependencies: {stats['packages_with_parents']}")
            print(f"   - Root packages (no parents): {stats['packages_without_parents']}")
            print(f"   - Total dependency relationships: {stats['total_dependency_edges']}")
            
            if stats['total_dependency_edges'] == 0:
                print("⚠️  WARNING: No dependency relationships found in SBOM!")
                print("   All packages will be marked as 'direct dependencies'")
            
            return True
            
        except FileNotFoundError as e:
            print(f"❌ Error: Required file not found: {e}", file=sys.stderr)
            return False
        except json.JSONDecodeError as e:
            print(f"❌ Error: Invalid JSON: {e}", file=sys.stderr)
            return False
    
    def get_ecosystem_vulnerabilities(self) -> Dict[Tuple[str, str, str], dict]:
        """
        Extract vulnerabilities from Trivy report for supported ecosystems.
        Returns dict mapping (CVE, PkgName, Version) to vulnerability details.
        
        Supported ecosystems: python-pkg (pip), node-pkg (npm)
        """
        vulnerability_map = {}
        
        for result in self.trivy_data.get('Results', []):
            result_type = result.get('Type', '')
            
            # Determine ecosystem
            ecosystem = None
            if result_type == 'python-pkg':
                ecosystem = 'pypi'
            elif result_type in ('node-pkg', 'npm'):
                ecosystem = 'npm'
            else:
                continue
            
            for vuln in result.get('Vulnerabilities', []):
                pkg_name = vuln.get('PkgName', '')
                installed_version = vuln.get('InstalledVersion', '')
                vuln_id = vuln.get('VulnerabilityID', '')
                
                if pkg_name and installed_version and vuln_id:
                    # Use composite key
                    key = (vuln_id, pkg_name, installed_version)
                    if key not in vulnerability_map:
                        vulnerability_map[key] = {
                            'vuln': vuln,
                            'ecosystem': ecosystem
                        }
        
        return vulnerability_map
    
    def analyze_dependency(self, package_name: str, version: str, ecosystem: str) -> dict:
        """
        Analyze dependency chain for a vulnerable package.
        
        Returns:
        {
            'is_direct': bool,
            'root_paths': List[List[str]],  # List of dependency paths
            'status': 'resolved' | 'version_mismatch' | 'unresolved',
            'matched_purl': str | None,
            'has_circular': bool
        }
        """
        # Try exact match first
        exact_purl = self.dependency_graph.find_exact_purl(package_name, version, ecosystem)
        
        if exact_purl:
            root_paths = self.dependency_graph.get_root_paths(exact_purl)
            is_direct = self.dependency_graph.is_direct_dependency(exact_purl)
            has_circular = any(len(path) != len(set(path)) for path in root_paths)
            
            return {
                'is_direct': is_direct,
                'root_paths': root_paths,
                'status': 'resolved',
                'matched_purl': exact_purl,
                'has_circular': has_circular
            }
        
        # Fallback: name-based matching (version mismatch)
        package_purls = self.dependency_graph.find_package_by_name(package_name)
        
        if not package_purls:
            return {
                'is_direct': False,
                'root_paths': [],
                'status': 'unresolved',
                'matched_purl': None,
                'has_circular': False
            }
        
        # Use first match (sorted for determinism)
        fallback_purl = sorted(package_purls)[0]
        root_paths = self.dependency_graph.get_root_paths(fallback_purl)
        is_direct = self.dependency_graph.is_direct_dependency(fallback_purl)
        has_circular = any(len(path) != len(set(path)) for path in root_paths)
        
        return {
            'is_direct': is_direct,
            'root_paths': root_paths,
            'status': 'version_mismatch',
            'matched_purl': fallback_purl,
            'has_circular': has_circular
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
        """Enrich SARIF file with multi-ecosystem dependency analysis."""
        # Show dependency graph statistics first
        print(f"\n📊 Dependency Graph Statistics:")
        stats = self.dependency_graph.get_stats()
        print(f"   Total unique purls: {stats['total_components']}")
        print(f"   Total component instances: {stats['total_component_instances']}")
        if stats['total_component_instances'] > stats['total_components']:
            print(f"   ⚠️  Detected {stats['total_component_instances'] - stats['total_components']} duplicate purls (multiple instances)")
        print(f"   Packages with parents: {stats['packages_with_parents']}")
        print(f"   Packages without parents (direct deps): {stats['packages_without_parents']}")
        print(f"   Total dependency edges: {stats['total_dependency_edges']}")
        
        if stats['total_dependency_edges'] == 0:
            print(f"\n⚠️  WARNING: No dependency relationships found in SBOM!")
            print(f"   This means:")
            print(f"   - All packages will be classified as 'direct'")
            print(f"   - No transitive dependency chains can be shown")
            print(f"   - The extract_container_deps.py script may have failed")
        
        vuln_map = self.get_ecosystem_vulnerabilities()
        
        if not vuln_map:
            print("ℹ️  No ecosystem vulnerabilities found. SARIF unchanged.")
            return True
        
        print(f"🔍 Found {len(vuln_map)} unique vulnerabilities to enrich")
        
        enriched_count = 0
        unresolved_count = 0
        version_mismatch_count = 0
        
        # Process each SARIF run
        for run in self.sarif_data.get('runs', []):
            results = run.get('results', [])
            
            for result in results:
                # Extract vulnerability information from SARIF result
                rule_id = result.get('ruleId', '')  # CVE ID
                
                # Extract package name and version from message
                pkg_name, pkg_version = self._extract_package_info_from_result(result)
                
                if not pkg_name or not pkg_version or not rule_id:
                    continue
                
                # Look up vulnerability using composite key
                vuln_key = (rule_id, pkg_name, pkg_version)
                vuln_data = vuln_map.get(vuln_key)
                
                if not vuln_data:
                    # Try alternate keys (case variations)
                    for key in vuln_map.keys():
                        if key[0] == rule_id and key[1].lower() == pkg_name.lower() and key[2] == pkg_version:
                            vuln_data = vuln_map[key]
                            break
                
                if not vuln_data:
                    continue
                
                ecosystem = vuln_data['ecosystem']
                
                # Analyze dependency
                analysis = self.analyze_dependency(pkg_name, pkg_version, ecosystem)
                
                # Build enrichment text
                enrichment = self._build_enrichment_text(pkg_name, pkg_version, analysis)
                
                # Append to message
                current_message = result['message']['text']
                result['message']['text'] = f"{current_message}\n\n{enrichment}"
                
                enriched_count += 1
                if analysis['status'] == 'unresolved':
                    unresolved_count += 1
                elif analysis['status'] == 'version_mismatch':
                    version_mismatch_count += 1
        
        print(f"✅ Enriched {enriched_count} vulnerabilities")
        if version_mismatch_count > 0:
            print(f"⚠️  {version_mismatch_count} vulnerabilities used version fallback")
        if unresolved_count > 0:
            print(f"⚠️  {unresolved_count} vulnerabilities could not be mapped to SBOM")
        
        return True
    
    def _extract_package_info_from_result(self, result: dict) -> Tuple[Optional[str], Optional[str]]:
        """
        Extract package name and version from SARIF result.
        Returns (package_name, version) or (None, None) if not found.
        """
        message = result.get('message', {}).get('text', '')
        lines = message.split('\n')
        
        pkg_name = None
        pkg_version = None
        
        # Parse Trivy message format
        for line in lines:
            line_stripped = line.strip()
            
            # Look for Package: or PkgName:
            if line_stripped.startswith('Package:'):
                pkg_name = line_stripped.split(':', 1)[1].strip()
            elif line_stripped.startswith('PkgName:'):
                pkg_name = line_stripped.split(':', 1)[1].strip()
            
            # Look for Installed Version: or InstalledVersion:
            if line_stripped.startswith('Installed Version:'):
                pkg_version = line_stripped.split(':', 1)[1].strip()
            elif line_stripped.startswith('InstalledVersion:'):
                pkg_version = line_stripped.split(':', 1)[1].strip()
            elif line_stripped.startswith('Version:') and not pkg_version:
                pkg_version = line_stripped.split(':', 1)[1].strip()
        
        # Fallback: parse purl if present
        if not pkg_name or not pkg_version:
            for line in lines:
                if 'pkg:' in line:
                    match = re.search(r'pkg:(pypi|npm)/([^@\s]+)@([^\s]+)', line)
                    if match:
                        if not pkg_name:
                            pkg_name = match.group(2)
                        if not pkg_version:
                            pkg_version = match.group(3)
        
        return (pkg_name, pkg_version)
    
    def _build_enrichment_text(self, package_name: str, version: str, analysis: dict) -> str:
        """Build enrichment text for SARIF message."""
        if analysis['status'] == 'unresolved':
            return (
                "─────────────────────────────────\n"
                "📦 Dependency Analysis:\n"
                f"   Package: {package_name}\n"
                f"   Version: {version}\n"
                "   Status: Could not resolve dependency chain\n"
                "   Note: Package not found in SBOM"
            )
        
        text_parts = [
            "─────────────────────────────────",
            "📦 Dependency Analysis:"
        ]
        
        # Check if we have any dependency information at all
        total_edges = sum(len(parents) for parents in self.dependency_graph.parents.values())
        
        version_mismatch_note = ""
        if analysis['status'] == 'version_mismatch':
            matched_version = self.dependency_graph._get_version_from_purl(analysis['matched_purl'])
            version_mismatch_note = f" (matched version {matched_version} in SBOM)"
        
        if analysis['is_direct']:
            if total_edges == 0:
                text_parts.append(f"   • Direct dependency: ✓ (no dependency relationships in SBOM)")
                text_parts.append(f"   • Package: {package_name}@{version}")
            else:
                text_parts.append(f"   • Direct dependency: ✓{version_mismatch_note}")
                text_parts.append(f"   • Package: {package_name}@{version}")
        else:
            text_parts.append(f"   • Direct dependency: ✗ (transitive){version_mismatch_note}")
            text_parts.append(f"   • Vulnerable package: {package_name}@{version}")
            
            root_paths = analysis['root_paths']
            if root_paths:
                # Show all paths (user wants to see all paths)
                text_parts.append(f"   • Dependency chain{' (multiple paths)' if len(root_paths) > 1 else ''}:")
                
                # Sort by length (shortest first) and show ALL paths
                for idx, path in enumerate(sorted(root_paths, key=len)):
                    formatted_path = self.format_dependency_path(path)
                    text_parts.append(f"     {formatted_path}")

            else:
                # Transitive but no paths found (shouldn't happen with correct graph)
                text_parts.append(f"   • Dependency chain: Unable to trace to root")
                text_parts.append(f"   • Note: Package has dependencies but path resolution failed")
        
        if analysis['has_circular']:
            text_parts.append(f"   • Circular dependency: ✓ (detected in graph)")
        
        if analysis['status'] == 'version_mismatch':
            text_parts.append(f"   • Version matched exactly: ✗ (using fallback)")
        
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
                print("❌ SARIF missing 'runs' field", file=sys.stderr)
                return False
            
            for run in self.sarif_data['runs']:
                if 'tool' not in run or 'results' not in run:
                    print("❌ SARIF run missing required fields", file=sys.stderr)
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
