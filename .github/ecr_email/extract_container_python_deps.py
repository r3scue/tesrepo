#!/usr/bin/env python3
"""
Extract Python dependency graph from container image metadata.

This script reads Python package metadata (METADATA/PKG-INFO files) directly
from a container image to build accurate dependency relationships, then
enhances the Trivy-generated SBOM with this information.

Usage:
    python3 extract_container_python_deps.py <image-uri> <trivy-sbom.json> <enhanced-sbom.json>

Example:
    python3 extract_container_python_deps.py \\
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


class ContainerPythonAnalyzer:
    """Extract Python dependency information from container images."""
    
    def __init__(self, image_uri: str):
        self.image_uri = image_uri
        self.dependency_map: Dict[str, List[str]] = {}
        self.package_versions: Dict[str, str] = {}
    
    def find_python_paths(self) -> List[str]:
        """Find all Python site-packages directories in container."""
        cmd = [
            'docker', 'run', '--rm', self.image_uri, 'sh', '-c',
            'find /usr/local/lib /usr/lib /opt -type d -name "site-packages" 2>/dev/null || true'
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            paths = [p.strip() for p in result.stdout.split('\n') if p.strip()]
            print(f"🐍 Found {len(paths)} Python site-packages directories")
            return paths
        except subprocess.TimeoutExpired:
            print("⚠️  Timeout finding Python paths")
            return []
        except Exception as e:
            print(f"⚠️  Error finding Python paths: {e}")
            return []
    
    def find_metadata_files(self, site_packages_paths: List[str]) -> List[str]:
        """Find all Python package metadata files."""
        metadata_files = []
        
        for site_path in site_packages_paths:
            # Look for .dist-info and .egg-info directories
            cmd = [
                'docker', 'run', '--rm', self.image_uri, 'sh', '-c',
                f'find {site_path} -type f \\( -name "METADATA" -o -name "PKG-INFO" \\) 2>/dev/null || true'
            ]
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                files = [f.strip() for f in result.stdout.split('\n') if f.strip()]
                metadata_files.extend(files)
            except Exception as e:
                print(f"⚠️  Error searching {site_path}: {e}")
                continue
        
        print(f"📦 Found {len(metadata_files)} package metadata files")
        return metadata_files
    
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
    
    def parse_metadata(self, content: str) -> Tuple[Optional[str], Optional[str], List[str]]:
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
                # Parse: Requires-Dist: requests (>=2.0.0); extra == 'security'
                dep_spec = line.split(':', 1)[1].strip()
                
                # Skip conditional dependencies (extras, markers)
                if ';' in dep_spec:
                    # Only include if it's not conditional or is a basic condition
                    parts = dep_spec.split(';')
                    dep_main = parts[0].strip()
                    condition = parts[1].strip().lower()
                    
                    # Skip extra dependencies and complex markers
                    if 'extra ==' in condition or 'platform_' in condition or 'python_version' in condition:
                        continue
                    
                    dep_spec = dep_main
                
                # Extract package name (before version specifier)
                dep_name = re.split(r'[<>=!(\s\[]', dep_spec)[0].strip().lower()
                
                if dep_name and dep_name not in dependencies:
                    dependencies.append(dep_name)
        
        return package_name, version, dependencies
    
    def extract_all_dependencies(self) -> None:
        """Extract dependency information from all packages in container."""
        print(f"\n🔍 Analyzing container: {self.image_uri}")
        
        # Find Python paths
        site_packages_paths = self.find_python_paths()
        if not site_packages_paths:
            print("⚠️  No Python site-packages found in container")
            return
        
        # Find metadata files
        metadata_files = self.find_metadata_files(site_packages_paths)
        if not metadata_files:
            print("⚠️  No Python package metadata found")
            return
        
        # Parse each metadata file
        print(f"\n📖 Parsing package metadata...")
        parsed_count = 0
        
        for metadata_path in metadata_files:
            content = self.read_container_file(metadata_path)
            if not content:
                continue
            
            pkg_name, version, deps = self.parse_metadata(content)
            
            if pkg_name:
                self.dependency_map[pkg_name] = deps
                if version:
                    self.package_versions[pkg_name] = version
                parsed_count += 1
                
                if parsed_count <= 3:  # Show first few as examples
                    print(f"   ✓ {pkg_name} {version or ''}: {len(deps)} dependencies")
        
        print(f"\n✅ Parsed {parsed_count} packages")
        total_deps = sum(len(deps) for deps in self.dependency_map.values())
        print(f"📊 Total dependency relationships: {total_deps}")
    
    def get_stats(self) -> Dict:
        """Get statistics about extracted dependencies."""
        total_packages = len(self.dependency_map)
        total_edges = sum(len(deps) for deps in self.dependency_map.values())
        packages_with_deps = sum(1 for deps in self.dependency_map.values() if deps)
        
        return {
            'total_packages': total_packages,
            'total_dependency_edges': total_edges,
            'packages_with_dependencies': packages_with_deps,
            'packages_without_dependencies': total_packages - packages_with_deps
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
        package_versions: Dict[str, str]
    ) -> None:
        """Add dependency relationships to SBOM."""
        
        # Build mapping of package name -> bom-ref
        ref_map = {}
        purl_map = {}
        
        for component in self.sbom.get('components', []):
            name = component.get('name', '').lower()
            ref = component.get('bom-ref')
            purl = component.get('purl', '')
            
            if name and ref:
                ref_map[name] = ref
            if purl:
                # Extract package name from purl
                # Format: pkg:pypi/package-name@version
                match = re.search(r'pkg:pypi/([^@]+)', purl, re.IGNORECASE)
                if match:
                    purl_name = match.group(1).lower()
                    purl_map[purl_name] = ref
        
        print(f"\n🔗 Building dependency relationships...")
        print(f"   SBOM components: {len(self.sbom.get('components', []))}")
        print(f"   Resolved references: {len(ref_map)}")
        
        # Create dependencies section
        dependencies = []
        matched_packages = 0
        total_edges = 0
        
        for component in self.sbom.get('components', []):
            name = component.get('name', '').lower()
            ref = component.get('bom-ref')
            
            if not ref:
                continue
            
            # Get dependencies for this package
            deps = dependency_map.get(name, [])
            depends_on = []
            
            for dep_name in deps:
                # Try exact match first
                dep_ref = ref_map.get(dep_name)
                
                # Try with underscores/hyphens normalization
                if not dep_ref:
                    dep_normalized = dep_name.replace('-', '_')
                    dep_ref = ref_map.get(dep_normalized)
                
                if not dep_ref:
                    dep_normalized = dep_name.replace('_', '-')
                    dep_ref = ref_map.get(dep_normalized)
                
                # Try purl map
                if not dep_ref:
                    dep_ref = purl_map.get(dep_name)
                
                if dep_ref and dep_ref != ref:  # Avoid self-reference
                    depends_on.append(dep_ref)
            
            if depends_on:
                matched_packages += 1
                total_edges += len(depends_on)
            
            dependencies.append({
                'ref': ref,
                'dependsOn': depends_on
            })
        
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
        print("\nUsage: python3 extract_container_python_deps.py <image-uri> <input-sbom.json> <output-sbom.json>")
        sys.exit(1)
    
    image_uri = sys.argv[1]
    input_sbom = sys.argv[2]
    output_sbom = sys.argv[3]
    
    # Validate inputs
    if not Path(input_sbom).exists():
        print(f"❌ Error: Input SBOM not found: {input_sbom}")
        sys.exit(1)
    
    print("=" * 70)
    print("🐋 Container Python Dependency Extractor")
    print("=" * 70)
    
    # Step 1: Extract dependencies from container
    analyzer = ContainerPythonAnalyzer(image_uri)
    analyzer.extract_all_dependencies()
    
    stats = analyzer.get_stats()
    if stats['total_packages'] == 0:
        print("\n❌ No Python packages found in container")
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
        analyzer.package_versions
    )
    enhancer.save(output_sbom)
    
    print("\n" + "=" * 70)
    print("✅ Dependency extraction complete!")
    print("=" * 70)
    print(f"\n📊 Summary:")
    print(f"   - Container: {image_uri}")
    print(f"   - Packages analyzed: {stats['total_packages']}")
    print(f"   - Dependency relationships: {stats['total_dependency_edges']}")
    print(f"   - Enhanced SBOM: {output_sbom}")
    print()


if __name__ == '__main__':
    main()
