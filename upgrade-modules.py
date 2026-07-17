#!/usr/bin/env python3
"""
Upgrade NawaSec Audit modules to v2.1.0 format
Adds missing explanation, risk, impact, recommendation, example, reference parameters
"""

import re
import sys
from pathlib import Path

# Default values for missing parameters
DEFAULTS = {
    'explanation': '',
    'risk': '',
    'impact': '',
    'recommendation': '',
    'example': '',
    'reference': ''
}

def upgrade_add_result_calls(content: str, module_name: str) -> str:
    """Upgrade add_result calls to include all parameters"""
    
    # Pattern to match add_result calls
    # This handles multi-line calls with backslash continuation
    pattern = r'add_result\s+"([^"]+)"\s+"([^"]+)"\s+"([^"]+)"\s+"([^"]+)"\s+"([^"]+)"(?:\s*\\\s*\n\s*"([^"]*)")?(?:\s*\\\s*\n\s*"([^"]*)")?(?:\s*\\\s*\n\s*"([^"]*)")?(?:\s*\\\s*\n\s*"([^"]*)")?(?:\s*\\\s*\n\s*"([^"]*)")?(?:\s*\\\s*\n\s*"([^"]*)")?'
    
    def replace_match(match):
        groups = match.groups()
        category = groups[0]
        name = groups[1]
        status = groups[2]
        severity = groups[3]
        message = groups[4]
        
        # Get existing parameters or use defaults
        explanation = groups[5] if groups[5] else DEFAULTS['explanation']
        risk = groups[6] if groups[6] else DEFAULTS['risk']
        impact = groups[7] if groups[7] else DEFAULTS['impact']
        recommendation = groups[8] if groups[8] else DEFAULTS['recommendation']
        example = groups[9] if groups[9] else DEFAULTS['example']
        reference = groups[10] if groups[10] else DEFAULTS['reference']
        
        # Build the new call
        result = f'add_result "{category}" "{name}" "{status}" "{severity}" \\\n'
        result += f'    "{message}" \\\n'
        result += f'    "{explanation}" \\\n'
        result += f'    "{risk}" \\\n'
        result += f'    "{impact}" \\\n'
        result += f'    "{recommendation}" \\\n'
        result += f'    "{example}" "{reference}"'
        
        return result
    
    # Replace all add_result calls
    upgraded = re.sub(pattern, replace_match, content, flags=re.DOTALL)
    
    return upgraded

def upgrade_module(module_path: Path, module_name: str):
    """Upgrade a single module"""
    
    script_path = module_path / f"audit-{module_name}.sh"
    
    if not script_path.exists():
        print(f"❌ {module_name}: Script not found at {script_path}")
        return False
    
    print(f"📦 Upgrading {module_name}...")
    
    # Read original
    content = script_path.read_text()
    
    # Backup
    backup_path = script_path.with_suffix('.sh.backup.v1')
    backup_path.write_text(content)
    
    # Count original calls
    original_count = content.count('add_result')
    
    # Upgrade
    upgraded = upgrade_add_result_calls(content, module_name)
    
    # Count upgraded calls
    upgraded_count = upgraded.count('add_result')
    
    # Update version
    upgraded = re.sub(
        r'VERSION="[^"]*"',
        'VERSION="2.1.0"',
        upgraded
    )
    
    # Write upgraded script
    script_path.write_text(upgraded)
    script_path.chmod(0o755)
    
    print(f"  ✅ {module_name}: {original_count} calls upgraded")
    print(f"  📁 Backup: {backup_path}")
    
    return True

def main():
    """Main function"""
    
    print("=== Upgrading NawaSec Audit Modules to v2.1.0 ===")
    print()
    
    # Get script directory
    script_dir = Path(__file__).parent
    
    # Modules to upgrade
    modules = ['apache', 'nginx', 'cpanel']
    
    success_count = 0
    
    for module in modules:
        module_path = script_dir / module
        if upgrade_module(module_path, module):
            success_count += 1
    
    print()
    print(f"=== Upgrade Complete: {success_count}/{len(modules)} modules upgraded ===")
    print()
    print("Next steps:")
    print("1. Test each module: sudo ./audit-<module>.sh --all")
    print("2. Update README files")
    print("3. Push to GitHub")
    
    return 0 if success_count == len(modules) else 1

if __name__ == '__main__':
    sys.exit(main())
