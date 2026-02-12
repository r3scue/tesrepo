#!/usr/bin/env python3
"""
Extract dependency graph from container image metadata for multiple ecosystems.

Supports: Python (pip), Node.js (npm)

This script reads package metadata files directly from a container image to build
accurate dependency relationships, then enhances the Trivy-generated SBOM.

Usage:
    python3 extract_container_deps.py <image-uri> <trivy-sbom.json> <enhanced-sbom.json>

Example:
    python3 extract_container_deps.py \\
        myregistry.com/myapp:latest \\
        sbom-base.json \\
        sbom-enhanced.json
"""

import json
import subprocess
import re
import sys
from typing import Dict, List, Set, Optional, Tuple
from collections import defaultdict
from pathlib import Path


class ContainerDependencyAnalyzer:
    """Extract dependency information from container images for multiple ecosystems."""
    
    def __init__(self, image_uri: str):
        self.image_uri = image_uri
        self.dependency_map: Dict[str, List[str]] = {}
        self.package_versions: Dict[str, str] = {}
        self.package_ecosystem: Dict[str, str] = {}  # Track which ecosystem each package belongs to
    
    def read_container_file(self, file_path: str) -> Optional[str]:
        """Read a file from the container."""
        cmd = ['docker', 'run', '--rm', self.image_uri, 'cat', file_path]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return result.stdout
            return None
        except Exception:
            return None
    
    def run_container_command(self, command: str, timeout: int = 30) -> Tuple[int, str]:
        """Run a shell command in the container."""
        cmd = ['docker', 'run', '--rm', self.image_uri, 'sh', '-c', command]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result.returncode, result.stdout
        except subprocess.TimeoutExpired:
            return 1, ""
        except Exception:
            return 1, ""
    
    # ============================================================================
    # PYTHON ECOSYSTEM
    # ============================================================================
    
    def find_python_paths(self) -> List[str]:
        """Find all Python site-packages directories in container."""
        code, output = self.run_container_command(
            'find /usr/local/lib /usr/lib /opt -type d -name "site-packages" 2>/dev/null || true'
        )
        
        paths = [p.strip() for p in output.split('\n') if p.strip()]
        if paths:
            print(f"🐍 Found {len(paths)} Python site-packages directories")
        return paths
    
    def find_python_metadata_files(self, site_packages_paths: List[str]) -> List[str]:
        """Find all Python package metadata files."""
        metadata_files = []
        
        for site_path in site_packages_paths:
            code, output = self.run_container_command(
                f'find {site_path} -type f \\( -name "METADATA" -o -name "PKG-INFO" \\) 2>/dev/null || true'
            )
            
            files = [f.strip() for f in output.split('\n') if f.strip()]
            metadata_files.extend(files)
        
        if metadata_files:
            print(f"📦 Found {len(metadata_files)} Python package metadata files")
        return metadata_files
    
    def parse_python_metadata(self, content: str) -> Tuple[Optional[str], Optional[str], List[str]]:
        """
        Parse Python package METADATA/PKG-INFO file.
        
        Returns:
            (package_name, version, list_of_dependencies)
        """
        package_name = None
        version = None
        dependencies = []
        
        for line in content.split('\n'):
            line = line.strip()
            
            if line.startswith('Name: '):
                package_name = line.split(':', 1)[1].strip().lower()
            
            elif line.startswith('Version: '):
                version = line.split(':', 1)[1].strip()
            
            elif line.startswith('Requires-Dist: '):
                dep_spec = line.split(':', 1)[1].strip()
                
                # Handle conditional dependencies (markers)
                if ';' in dep_spec:
                    parts = dep_spec.split(';')
                    dep_main = parts[0].strip()
                    condition = parts[1].strip().lower()
                    
                    # Only skip "extra ==" dependencies (optional features)
                    # Keep everything else including python_version, platform, etc.
                    # These are real dependencies that are used in the container
                    if 'extra ==' in condition:
                        continue
                    
                    dep_spec = dep_main
                
                # Extract package name (before version specifier)
                dep_name = re.split(r'[<>=!(\s\[]', dep_spec)[0].strip().lower()
                
                if dep_name and dep_name not in dependencies:
                    dependencies.append(dep_name)
        
        return package_name, version, dependencies
    
    def extract_python_dependencies(self) -> int:
        """Extract Python dependency information from container."""
        print(f"\n🐍 Analyzing Python packages...")
        
        site_packages_paths = self.find_python_paths()
        if not site_packages_paths:
            print("   No Python packages found")
            return 0
        
        metadata_files = self.find_python_metadata_files(site_packages_paths)
        if not metadata_files:
            print("   No Python package metadata found")
            return 0
        
        print(f"   Parsing package metadata...")
        parsed_count = 0
        packages_with_deps = 0
        
        for metadata_path in metadata_files:
            content = self.read_container_file(metadata_path)
            if not content:
                continue
            
            pkg_name, version, deps = self.parse_python_metadata(content)
            
            if pkg_name:
                self.dependency_map[pkg_name] = deps
                self.package_ecosystem[pkg_name] = 'pypi'
                if version:
                    self.package_versions[pkg_name] = version
                parsed_count += 1
                
                if deps:
                    packages_with_deps += 1
                
                # Show more samples including ones WITH dependencies
                if parsed_count <= 5 or (len(deps) > 0 and packages_with_deps <= 3):
                    dep_sample = deps[:3] if deps else []
                    print(f"   ✓ {pkg_name} {version or ''}: {len(deps)} deps {dep_sample}")
        
        print(f"   ✅ Parsed {parsed_count} Python packages")
        print(f"      {packages_with_deps} packages have dependencies")
        return parsed_count
    
    # ============================================================================
    # NODE.JS / NPM ECOSYSTEM
    # ============================================================================
    
    def find_node_modules_paths(self) -> List[str]:
        """Find all node_modules directories in container."""
        code, output = self.run_container_command(
            'find /usr/local /usr/lib /opt /app /home -type d -name "node_modules" 2>/dev/null || true',
            timeout=45
        )
        
        paths = [p.strip() for p in output.split('\n') if p.strip()]
        if paths:
            print(f"📦 Found {len(paths)} node_modules directories")
        return paths
    
    def find_npm_package_files(self, node_modules_paths: List[str]) -> List[str]:
        """Find all package.json files in node_modules."""
        package_files = []
        
        for nm_path in node_modules_paths:
            # Find all package.json files within this node_modules
            # Use maxdepth 2 for top-level packages (e.g., node_modules/serverless/package.json)
            # This is faster and package-lock.json handles nested dependencies
            code, output = self.run_container_command(
                f'find {nm_path} -maxdepth 2 -type f -name "package.json" 2>/dev/null || true',
                timeout=30
            )
            
            files = [f.strip() for f in output.split('\n') if f.strip()]
            package_files.extend(files)
        
        if package_files:
            print(f"📦 Found {len(package_files)} npm package.json files")
        return package_files
    
    def parse_npm_package_json(self, content: str) -> Tuple[Optional[str], Optional[str], List[str]]:
        """
        Parse npm package.json file.
        
        Returns:
            (package_name, version, list_of_dependencies)
        """
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return None, None, []
        
        package_name = data.get('name', '').lower()
        version = data.get('version')
        
        # Collect dependencies from multiple sections
        dependencies = []
        
        # Regular dependencies
        for dep in data.get('dependencies', {}).keys():
            dep_normalized = dep.lower()
            if dep_normalized not in dependencies:
                dependencies.append(dep_normalized)
        
        # Peer dependencies (important for npm ecosystem)
        for dep in data.get('peerDependencies', {}).keys():
            dep_normalized = dep.lower()
            if dep_normalized not in dependencies:
                dependencies.append(dep_normalized)
        
        # Optional dependencies
        for dep in data.get('optionalDependencies', {}).keys():
            dep_normalized = dep.lower()
            if dep_normalized not in dependencies:
                dependencies.append(dep_normalized)
        
        return package_name, version, dependencies
    
    def find_package_lock_files(self) -> List[str]:
        """Find package-lock.json files in the container."""
        code, output = self.run_container_command(
            'find /usr/local /usr/lib /opt /app /home -type f -name "package-lock.json" 2>/dev/null || true',
            timeout=30
        )
        
        files = [f.strip() for f in output.split('\n') if f.strip()]
        if files:
            print(f"🔒 Found {len(files)} package-lock.json files")
        return files
    
    def parse_package_lock_json(self, content: str) -> Dict[str, List[str]]:
        """
        Parse package-lock.json to extract complete dependency tree.
        Returns dict mapping package names to their direct dependencies.
        """
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return {}
        
        dependencies = {}
        lockfile_version = data.get('lockfileVersion', 1)
        
        if lockfile_version >= 2:
            # Modern format (v2/v3) uses "packages" with node_modules paths
            packages = data.get('packages', {})
            
            for pkg_path, pkg_data in packages.items():
                # Skip root package entry
                if pkg_path == '':
                    continue
                
                # Extract package name from path like "node_modules/tar" or "node_modules/serverless/node_modules/tar"
                if pkg_path.startswith('node_modules/'):
                    pkg_name = pkg_path.split('node_modules/')[-1]
                    pkg_name = pkg_name.lower()
                    
                    # Get dependencies
                    deps = []
                    for dep in pkg_data.get('dependencies', {}).keys():
                        deps.append(dep.lower())
                    
                    if pkg_name:
                        dependencies[pkg_name] = deps
        else:
            # Legacy format (v1) uses "dependencies" object
            def extract_v1_deps(deps_obj: dict, dependencies: dict):
                """Recursively extract dependencies from v1 format."""
                for pkg_name, pkg_data in deps_obj.items():
                    pkg_name_lower = pkg_name.lower()
                    requires = pkg_data.get('requires', {})
                    dependencies[pkg_name_lower] = [dep.lower() for dep in requires.keys()]
                    
                    # Recurse into nested dependencies
                    if 'dependencies' in pkg_data:
                        extract_v1_deps(pkg_data['dependencies'], dependencies)
            
            extract_v1_deps(data.get('dependencies', {}), dependencies)
        
        return dependencies
    
    def extract_npm_dependencies(self) -> int:
        """Extract npm dependency information from container."""
        print(f"\n📦 Analyzing npm packages...")
        
        node_modules_paths = self.find_node_modules_paths()
        if not node_modules_paths:
            print("   No node_modules found")
            return 0
        
        packages_from_lock = set()  # Track packages from lock file
        
        # First, try to find and parse package-lock.json (most accurate for nested deps)
        lock_files = self.find_package_lock_files()
        packages_from_lock = set()
        if lock_files:
            print(f"   Using package-lock.json for nested dependency information...")
            for lock_file in lock_files:
                content = self.read_container_file(lock_file)
                if content:
                    lock_deps = self.parse_package_lock_json(content)
                    if lock_deps:
                        print(f"   ✓ Extracted {len(lock_deps)} packages from package-lock.json")
                        # Merge with existing dependency map
                        for pkg_name, deps in lock_deps.items():
                            self.dependency_map[pkg_name] = deps
                            self.package_ecosystem[pkg_name] = 'npm'
                            packages_from_lock.add(pkg_name)
                else:
                    print(f"   ⚠️ Could not read {lock_file}")
        
        # ALWAYS parse individual package.json files to get root-level packages
        # that might not be in lock files (especially for globally installed packages)
        print(f"   Parsing individual package.json files for top-level packages...")
        package_files = self.find_npm_package_files(node_modules_paths)
        if not package_files:
            print("   No npm packages found")
            if packages_from_lock:
                print(f"   ✅ Using {len(packages_from_lock)} packages from package-lock.json only")
                return len(packages_from_lock)
            return 0
        
        print(f"   Found {len(package_files)} package.json files to parse...")
        parsed_count = 0
        skipped_count = 0
        
        for package_path in package_files:
            
            content = self.read_container_file(package_path)
            if not content:
                continue
            
            pkg_name, version, deps = self.parse_npm_package_json(content)
            
            if pkg_name and pkg_name not in ['', '.', 'undefined']:
                # Skip if already parsed from package-lock.json (lock file is more accurate)
                if pkg_name in packages_from_lock:
                    skipped_count += 1
                    continue
                
                # Handle scoped packages (e.g., @types/node)
                self.dependency_map[pkg_name] = deps
                self.package_ecosystem[pkg_name] = 'npm'
                if version:
                    self.package_versions[pkg_name] = version
                parsed_count += 1
                
                if parsed_count <= 3:
                    print(f"   ✓ {pkg_name} {version or ''}: {len(deps)} dependencies")
        
        total_npm = len(packages_from_lock) + parsed_count
        print(f"   ✅ Parsed {parsed_count} npm packages from package.json (skipped {skipped_count} already in lock file)")
        print(f"   ✅ Total npm packages: {total_npm}")
        return total_npm
    
    # ============================================================================
    # MAIN EXTRACTION
    # ============================================================================
    
    def extract_all_dependencies(self) -> None:
        """Extract dependency information for all supported ecosystems."""
        print(f"\n🔍 Analyzing container: {self.image_uri}")
        print("=" * 70)
        
        total_packages = 0
        
        # Extract Python dependencies
        total_packages += self.extract_python_dependencies()
        
        # Extract npm dependencies
        total_packages += self.extract_npm_dependencies()
        
        print("\n" + "=" * 70)
        print(f"✅ Total packages analyzed: {total_packages}")
        total_deps = sum(len(deps) for deps in self.dependency_map.values())
        print(f"📊 Total dependency relationships: {total_deps}")
    
    def get_stats(self) -> Dict:
        """Get statistics about extracted dependencies."""
        total_packages = len(self.dependency_map)
        total_edges = sum(len(deps) for deps in self.dependency_map.values())
        packages_with_deps = sum(1 for deps in self.dependency_map.values() if deps)
        
        # Count by ecosystem
        python_count = sum(1 for eco in self.package_ecosystem.values() if eco == 'pypi')
        npm_count = sum(1 for eco in self.package_ecosystem.values() if eco == 'npm')
        
        return {
            'total_packages': total_packages,
            'total_dependency_edges': total_edges,
            'packages_with_dependencies': packages_with_deps,
            'packages_without_dependencies': total_packages - packages_with_deps,
            'python_packages': python_count,
            'npm_packages': npm_count
        }


class SBOMEnhancer:
    """Enhance Trivy SBOM with extracted dependency information."""
    
    def __init__(self, sbom_path: str):
        self.sbom_path = sbom_path
        with open(sbom_path) as f:
            self.sbom = json.load(f)
    
    def enhance_with_dependencies(
        self, 
        dependency_map: Dict[str, List[str]],
        package_versions: Dict[str, str],
        package_ecosystem: Dict[str, str]
    ) -> None:
        """Add dependency relationships to SBOM."""
        
        # Build comprehensive mapping structures
        ref_map = {}  # name -> bom-ref
        purl_map = {}  # purl_name -> bom-ref
        ecosystem_ref_map = {}  # ecosystem:name -> bom-ref (for disambiguation)
        
        for component in self.sbom.get('components', []):
            name = component.get('name', '').lower()
            ref = component.get('bom-ref')
            purl = component.get('purl', '')
            
            if not ref:
                continue
            
            # Build name-based index (basic)
            if name:
                # Handle potential collisions: prefer exact ecosystem match later
                if name not in ref_map:
                    ref_map[name] = ref
            
            # Extract and index from purl
            if purl:
                # Determine ecosystem
                eco = None
                for eco_prefix in ['pkg:pypi/', 'pkg:npm/', 'pkg:deb/']:
                    if purl.lower().startswith(eco_prefix):
                        eco = eco_prefix.replace('pkg:', '').rstrip('/')
                        break
                
                # Extract package name from purl
                match = re.search(r'pkg:[^/]+/([^@?]+)', purl, re.IGNORECASE)
                if match:
                    purl_name = match.group(1).lower()
                    purl_map[purl_name] = ref
                    
                    # Also map with ecosystem prefix for disambiguation
                    if eco:
                        ecosystem_ref_map[f"{eco}:{purl_name}"] = ref
                        # Also map the simple name for this ecosystem
                        if name:
                            ecosystem_ref_map[f"{eco}:{name}"] = ref
                    
                    # Handle npm scoped packages (@scope/name → name)
                    if purl_name.startswith('@') and '/' in purl_name:
                        unscoped_name = purl_name.split('/')[-1]
                        if unscoped_name not in purl_map or eco == 'npm':
                            purl_map[unscoped_name] = ref
                    
                    # Handle name variations (underscore vs hyphen)
                    purl_name_underscore = purl_name.replace('-', '_')
                    purl_name_hyphen = purl_name.replace('_', '-')
                    if purl_name_underscore not in purl_map:
                        purl_map[purl_name_underscore] = ref
                    if purl_name_hyphen not in purl_map:
                        purl_map[purl_name_hyphen] = ref
        
        print(f"\n🔗 Building dependency relationships...")
        print(f"   SBOM components: {len(self.sbom.get('components', []))}")
        print(f"   Resolved references (ref_map): {len(ref_map)}")
        print(f"   Resolved PURLs (purl_map): {len(purl_map)}")
        print(f"   Ecosystem-specific refs: {len(ecosystem_ref_map)}")
        print(f"   Extracted dependency map: {len(dependency_map)} packages")
        
        # Debug: Show some sample entries
        if dependency_map:
            print(f"\n📋 Sample dependency_map entries:")
            for idx, (pkg, deps) in enumerate(list(dependency_map.items())[:5]):
                print(f"      {pkg}: {deps[:5]}")
        else:
            print(f"\n⚠️  WARNING: dependency_map is EMPTY!")
        
        # Debug: Show some sample ref_map entries for comparison
        if ref_map:
            print(f"\n📋 Sample ref_map entries (for matching):")
            pypi_count = 0
            npm_count = 0
            for name, ref in list(ref_map.items())[:10]:
                if 'pkg:pypi' in ref:
                    print(f"      {name} → {ref}")
                    pypi_count += 1
                elif 'pkg:npm' in ref:
                    print(f"      {name} → {ref}")
                    npm_count += 1
            print(f"   Total: {pypi_count} pypi, {npm_count} npm in sample")
        
        # Create dependencies section
        dependencies = []
        matched_packages = 0
        total_edges = 0
        unmatched_deps = defaultdict(list)  # Track which deps couldn't be matched
        
        for component in self.sbom.get('components', []):
            name = component.get('name', '').lower()
            ref = component.get('bom-ref')
            purl = component.get('purl', '')
            
            if not ref:
                continue
            
            # Determine ecosystem of this component
            component_ecosystem = None
            for eco_prefix in ['pkg:pypi/', 'pkg:npm/']:
                if purl.lower().startswith(eco_prefix):
                    component_ecosystem = eco_prefix.replace('pkg:', '').rstrip('/')
                    break
            
            # Get dependencies for this package
            deps = dependency_map.get(name, [])
            depends_on = []
            
            for dep_name in deps:
                dep_ref = None
                matched_method = None
                
                # Strategy 1: Try ecosystem-specific match first (most accurate)
                if component_ecosystem:
                    ecosystem_key = f"{component_ecosystem}:{dep_name}"
                    dep_ref = ecosystem_ref_map.get(ecosystem_key)
                    matched_method = "ecosystem-specific"
                
                # Strategy 2: Try exact name match in ref_map
                if not dep_ref:
                    dep_ref = ref_map.get(dep_name)
                    matched_method = "exact-name"
                
                # Strategy 3: Try purl_map (includes variations)
                if not dep_ref:
                    dep_ref = purl_map.get(dep_name)
                    matched_method = "purl"
                
                # Strategy 4: Try underscore normalization
                if not dep_ref:
                    dep_normalized = dep_name.replace('-', '_')
                    dep_ref = ref_map.get(dep_normalized) or purl_map.get(dep_normalized)
                    matched_method = "underscore"
                
                # Strategy 5: Try hyphen normalization
                if not dep_ref:
                    dep_normalized = dep_name.replace('_', '-')
                    dep_ref = ref_map.get(dep_normalized) or purl_map.get(dep_normalized)
                    matched_method = "hyphen"
                
                # Strategy 6: For npm scoped packages, try without scope
                if not dep_ref and '/' in dep_name:
                    unscoped = dep_name.split('/')[-1]
                    dep_ref = purl_map.get(unscoped)
                    matched_method = "unscoped"
                
                if dep_ref and dep_ref != ref:  # Avoid self-reference
                    depends_on.append(dep_ref)
                elif not dep_ref:
                    # Track unmatched for debugging
                    unmatched_deps[name].append(dep_name)
            
            if depends_on:
                matched_packages += 1
                total_edges += len(depends_on)
                # Debug: Show first few successful matches
                if matched_packages <= 3:
                    print(f"\n   ✓ {name} ({component_ecosystem}): {len(depends_on)} deps matched")
                    for dep_ref in depends_on[:3]:
                        print(f"      → {dep_ref}")
            
            dependencies.append({
                'ref': ref,
                'dependsOn': depends_on
            })
        
        # Show unmatched dependencies for debugging
        if unmatched_deps:
            print(f"\n⚠️  Unmatched dependencies (sample):")
            for pkg, deps in list(unmatched_deps.items())[:5]:
                print(f"      {pkg} → {deps[:5]}")
        
        # Update SBOM
        self.sbom['dependencies'] = dependencies
        
        print(f"   ✓ Created {len(dependencies)} dependency entries")
        print(f"   ✓ Matched {matched_packages} packages with dependencies")
        print(f"   ✓ Total dependency edges: {total_edges}")
        
        if total_edges == 0:
            print("\n⚠️  Warning: No dependency edges created!")
            print("   This might indicate:")
            print("   - Package names don't match between SBOM and metadata")
            print("   - Container has no dependent packages")
            print("   - Metadata files are incomplete")
    
    def save(self, output_path: str) -> None:
        """Save enhanced SBOM."""
        with open(output_path, 'w') as f:
            json.dump(self.sbom, f, indent=2)
        print(f"\n✅ Enhanced SBOM saved to: {output_path}")


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        print("\nError: Invalid arguments")
        print("\nUsage: python3 extract_container_deps.py <image-uri> <input-sbom.json> <output-sbom.json>")
        sys.exit(1)
    
    image_uri = sys.argv[1]
    input_sbom = sys.argv[2]
    output_sbom = sys.argv[3]
    
    # Validate inputs
    if not Path(input_sbom).exists():
        print(f"❌ Error: Input SBOM not found: {input_sbom}")
        sys.exit(1)
    
    print("=" * 70)
    print("🐋 Multi-Ecosystem Container Dependency Extractor")
    print("   Supports: Python (pip), Node.js (npm)")
    print("=" * 70)
    
    # Step 1: Extract dependencies from container
    analyzer = ContainerDependencyAnalyzer(image_uri)
    analyzer.extract_all_dependencies()
    
    stats = analyzer.get_stats()
    if stats['total_packages'] == 0:
        print("\n❌ No packages found in container")
        print("   Copying original SBOM unchanged...")
        import shutil
        shutil.copy(input_sbom, output_sbom)
        sys.exit(0)
    
    # Step 2: Enhance SBOM
    print("\n" + "=" * 70)
    print("🔧 Enhancing SBOM with dependency information")
    print("=" * 70)
    
    enhancer = SBOMEnhancer(input_sbom)
    enhancer.enhance_with_dependencies(
        analyzer.dependency_map,
        analyzer.package_versions,
        analyzer.package_ecosystem
    )
    enhancer.save(output_sbom)
    
    print("\n" + "=" * 70)
    print("✅ Dependency extraction complete!")
    print("=" * 70)
    print(f"\n📊 Summary:")
    print(f"   - Container: {image_uri}")
    print(f"   - Python packages: {stats['python_packages']}")
    print(f"   - npm packages: {stats['npm_packages']}")
    print(f"   - Total packages: {stats['total_packages']}")
    print(f"   - Dependency relationships: {stats['total_dependency_edges']}")
    print(f"   - Enhanced SBOM: {output_sbom}")
    print()


if __name__ == '__main__':
    main()
