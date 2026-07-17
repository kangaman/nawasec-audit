#!/usr/bin/env python3
"""
Add missing explanation, risk, impact, recommendation, example, reference parameters
to add_result calls in NawaSec Audit modules
"""

import re
import sys
from pathlib import Path

def add_missing_parameters(content: str, module_name: str) -> str:
    """Add missing parameters to add_result calls"""
    
    lines = content.split('\n')
    result_lines = []
    i = 0
    
    while i < len(lines):
        line = lines[i]
        
        # Check if this is an add_result call
        if 'add_result' in line and '"' in line:
            # Collect the full call (may span multiple lines)
            full_call = line
            while full_call.rstrip().endswith('\\'):
                i += 1
                if i < len(lines):
                    full_call += '\n' + lines[i]
                else:
                    break
            
            # Count the number of quoted parameters
            # Pattern: "value" or "value with spaces"
            quotes = re.findall(r'"([^"]*)"', full_call)
            
            # If we have less than 11 parameters, add missing ones
            if len(quotes) < 11:
                # Parse the existing parameters
                category = quotes[0] if len(quotes) > 0 else ''
                name = quotes[1] if len(quotes) > 1 else ''
                status = quotes[2] if len(quotes) > 2 else ''
                severity = quotes[3] if len(quotes) > 3 else ''
                message = quotes[4] if len(quotes) > 4 else ''
                explanation = quotes[5] if len(quotes) > 5 else ''
                risk = quotes[6] if len(quotes) > 6 else ''
                impact = quotes[7] if len(quotes) > 7 else ''
                recommendation = quotes[8] if len(quotes) > 8 else ''
                example = quotes[9] if len(quotes) > 9 else ''
                reference = quotes[10] if len(quotes) > 10 else ''
                
                # Build the new call with all parameters
                indent = '        '
                new_call = f'{indent}add_result "{category}" "{name}" "{status}" "{severity}" \\\n'
                new_call += f'{indent}    "{message}" \\\n'
                new_call += f'{indent}    "{explanation}" \\\n'
                new_call += f'{indent}    "{risk}" \\\n'
                new_call += f'{indent}    "{impact}" \\\n'
                new_call += f'{indent}    "{recommendation}" \\\n'
                new_call += f'{indent}    "{example}" "{reference}"'
                
                result_lines.append(new_call)
            else:
                result_lines.append(full_call)
        else:
            result_lines.append(line)
        
        i += 1
    
    return '\n'.join(result_lines)

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
    backup_path = script_path.with_suffix('.sh.backup.v2')
    backup_path.write_text(content)
    
    # Count original calls
    original_count = content.count('add_result')
    
    # Upgrade
    upgraded = add_missing_parameters(content, module_name)
    
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
