import subprocess
import os
import threading
import re
import datetime
import json
from typing import List, Tuple, Optional, Dict, Any, Pattern
#!/usr/bin/env python3
import sys
import re
import json
import shutil
import subprocess
from pathlib import Path
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Set, Tuple
from rich.console import Console
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

VERSION = "1.0"
AUTHOR = "Sandeep Wawdane"
ANDROID = "http://schemas.android.com/apk/res/android"
console = Console()

# ==================== CONFIGURACIÓN GLOBAL ====================
# Rutas de herramientas
TOOL_PATHS = {
    'adb': "./to/adb.exe",
    'fastboot': "./to/fastboot.exe",
    'frida': "frida",
    'apktool': "apktool",
    'uber_apk_signer': "java -jar uber-apk-singer.jar"
}

# Archivos de configuración
CONFIG_FILES = {
    'frida_hook': "hook.js",
    'url_results': {
        'text': "results.txt",
        'json': "results.json"
    }
}

# Patrones de expresión regular
REGEX_PATTERNS = {
    'camera': re.compile(
        r"CameraDevice|CameraManager|android\.hardware\.Camera|"
        r"libwebrtc|PeerConnection|SurfaceView|SurfaceTexture|TextureView|"
        r"MediaRecorder|openCamera|Camera permission|"
        r"Failed to connect camera|captureSession|onCameraOpened"
    ),
    'urls': [
        re.compile(r"https?://[^\s\"']+"),
        re.compile(r"https?://(?:[a-zA-Z0-9.-]*\.)?invertironline\.com[^\s\"']*"),
        re.compile(r"https?://(?:[a-zA-Z0-9.-]*\.)?iolinversiones\.com[^\s\"']*")
    ],
    'foreground_app': re.compile(r'mCurrentFocus.*? ([^/\s]+)/')
}

# Comandos ADB base
ADB_COMMANDS = {
    'devices': ["devices"],
    'shell': ["shell"],
    'reboot': ["reboot"],
    'install': ["install"],
    'uninstall': ["uninstall"],
    'pull': ["pull"],
    'logcat': ["logcat"],
    'disconnect': ["disconnect"]
}

# Comandos Fastboot base
FASTBOOT_COMMANDS = {
    'devices': ["devices"],
    'getvar': ["getvar", "all"],
    'oem_unlock': ["oem", "unlock"],
    'oem_lock': ["oem", "lock"],
    'erase': ["erase"],
    'flash': ["flash"],
    'reboot': ["reboot"],
    'edl': ["oem", "edl"]
}

# Comandos del sistema
SYSTEM_COMMANDS = {
       'shell': ["shell"], 
    'pm_list': ["pm", "list", "packages"],
    'pm_path': ["pm", "path"],
    'pm_clear': ["pm", "clear"],
    'am_force_stop': ["am", "force-stop"],
    'monkey': ["monkey", "-p"],
    'dumpsys': ["dumpsys"],
    'settings': ["settings", "put", "global", "verifier_verify_adb_installs", "0"]
}

# Variables de estado global
selected_device = None

@dataclass
class IntentExtra:
    name: str
    type: str
    required: bool = False
    default_value: Optional[str] = None

class SmaliAnalyzer:
    def __init__(self, decompiled_dir: str, verbose: bool = False, quiet: bool = False):
        self.decompiled_dir = Path(decompiled_dir)
        self.verbose = verbose
        self.quiet = quiet
        self.string_pool: Dict[str, str] = {}
        
    def find_smali_files(self, class_name: str) -> List[Path]:
        """Find all smali files for a class including inner classes"""
        base_path = class_name.replace('.', '/')
        files = []
        
        # Look for exact match and inner classes
        patterns = [
            f"{base_path}.smali",
            f"{base_path}$*.smali"
        ]
        
        for smali_dir in self.decompiled_dir.glob('smali*'):
            for pattern in patterns:
                files.extend(smali_dir.glob(pattern))
                
        return files

    def _extract_string_pool(self, content: str) -> Dict[str, str]:
        """Extract all string constants from smali file"""
        strings = {}
        for match in re.finditer(r'const-string(?:/jumbo)?\s+v(\d+),\s+"([^"\\]*(?:\\.[^"\\]*)*)"', content):
            reg = match.group(1)
            value = match.group(2)
            # Decode escape sequences
            value = value.replace('\\"', '"').replace('\\n', '\n').replace('\\t', '\t')
            strings[reg] = value
        return strings

    def _is_valid_extra_name(self, name: str) -> bool:
        """Filter out strings that are obviously not extra names"""
        # Filter out error messages and log strings
        invalid_patterns = [
            r'^[A-Z][a-z]+.*[.!?]$',  # Sentences ending with punctuation
            r'^\s*$',  # Empty or whitespace
            r'^.{50,}$',  # Too long (likely error messages)
            r'https?://',  # URLs
            r'www\.',  # Web addresses
            r'^Error:',  # Error messages
            r'^Exception',  # Exception messages
            r'null!',  # Null pointer messages
            r'was null',  # Null checks
            r'callback',  # Callback error messages
            r'Executor',  # Executor error messages
        ]
        
        # Valid extra names usually follow patterns
        valid_patterns = [
            r'^[a-zA-Z_][a-zA-Z0-9_]*$',  # Standard identifier
            r'^[a-z]+[_.]?[a-z]+$',  # snake_case or dot.case
            r'^[a-z]+[A-Z][a-zA-Z]*$',  # camelCase
            r'^[A-Z]+_[A-Z]+$',  # CONSTANT_CASE
        ]
        
        # Check invalid patterns
        for pattern in invalid_patterns:
            if re.search(pattern, name, re.IGNORECASE):
                return False
                
        # Check if it matches any valid pattern
        for pattern in valid_patterns:
            if re.match(pattern, name):
                return True
                
        # Additional checks
        if len(name) < 2 or len(name) > 40:
            return False
            
        # If it contains spaces and isn't matching valid patterns, it's likely not an extra
        if ' ' in name and not any(re.match(p, name) for p in valid_patterns):
            return False
            
        return True

    def _extract_extras_from_method(self, content: str, method_name: str) -> Dict[str, IntentExtra]:
        """Extract intent extras with improved detection"""
        extras: Dict[str, IntentExtra] = {}
        
        # Find method body
        method_pattern = rf'\.method\s+.*?\s+{method_name}\s*\([^)]*\).*?^\.end method'
        method_match = re.search(method_pattern, content, re.MULTILINE | re.DOTALL)
        if not method_match:
            return extras
            
        method_body = method_match.group(0)
        
        # Extract string pool for this method
        strings = self._extract_string_pool(method_body)
        
        # Pattern for different get*Extra methods
        extra_patterns = [
            (r'getStringExtra', 'string'),
            (r'getBooleanExtra', 'boolean'),
            (r'getIntExtra', 'int'),
            (r'getLongExtra', 'long'),
            (r'getFloatExtra', 'float'),
            (r'getDoubleExtra', 'double'),
            (r'getByteExtra', 'byte'),
            (r'getShortExtra', 'short'),
            (r'getCharExtra', 'char'),
            (r'getStringArrayExtra', 'string[]'),
            (r'getIntArrayExtra', 'int[]'),
            (r'getByteArrayExtra', 'byte[]'),
            (r'getCharArrayExtra', 'char[]'),
            (r'getFloatArrayExtra', 'float[]'),
            (r'getDoubleArrayExtra', 'double[]'),
            (r'getLongArrayExtra', 'long[]'),
            (r'getShortArrayExtra', 'short[]'),
            (r'getBooleanArrayExtra', 'boolean[]'),
            (r'getBundleExtra', 'bundle'),
            (r'getParcelableExtra', 'parcelable'),
            (r'getSerializableExtra', 'serializable'),
            (r'getStringArrayListExtra', 'ArrayList<String>'),
            (r'getIntegerArrayListExtra', 'ArrayList<Integer>'),
            (r'getParcelableArrayListExtra', 'ArrayList<Parcelable>'),
            (r'getCharSequenceExtra', 'CharSequence'),
            (r'getCharSequenceArrayExtra', 'CharSequence[]'),
            (r'getCharSequenceArrayListExtra', 'ArrayList<CharSequence>'),
        ]
        
        # Find all getExtra calls
        for extra_method, extra_type in extra_patterns:
            pattern = rf'invoke-virtual\s+\{{([^}}]+)\}},\s*Landroid/content/Intent;->{extra_method}'
            
            for match in re.finditer(pattern, method_body):
                # Get registers used
                regs = match.group(1).split(',')
                if len(regs) < 2:
                    continue
                    
                intent_reg = regs[0].strip()
                key_reg = regs[1].strip()
                
                # Find the string key
                if key_reg.startswith('v') and key_reg[1:] in strings:
                    key = strings[key_reg[1:]]
                    
                    # Validate the key is a valid extra name
                    if not self._is_valid_extra_name(key):
                        continue
                    
                    # Check if there's a null check after
                    pos = match.end()
                    next_lines = method_body[pos:pos+200]
                    
                    # Look for move-result and null check
                    required = False
                    default_value = None
                    
                    if 'move-result' in next_lines:
                        if re.search(r'if-(?:eq|ne)z\s+v\d+', next_lines):
                            required = True
                            
                    # For primitive types with default values
                    if extra_type in ['boolean', 'int', 'long', 'float', 'double', 'byte', 'short', 'char']:
                        # Look for default value parameter
                        if len(regs) > 2:
                            default_reg = regs[2].strip()
                            if default_reg.startswith('v') and default_reg[1:] in strings:
                                default_value = strings[default_reg[1:]]
                            elif re.match(r'^-?\d+$', default_reg):
                                default_value = default_reg
                    
                    if key not in extras or required:  # Prefer required extras
                        extras[key] = IntentExtra(
                            name=key,
                            type=extra_type,
                            required=required,
                            default_value=default_value
                        )
                        
        # Also check for getExtras() and Bundle operations
        if 'getExtras()' in method_body:
            bundle_pattern = r'invoke-virtual\s+\{([^}]+)\},\s*Landroid/os/Bundle;->get(\w+)'
            for match in re.finditer(bundle_pattern, method_body):
                regs = match.group(1).split(',')
                if len(regs) >= 2:
                    key_reg = regs[1].strip()
                    method_type = match.group(2)
                    
                    if key_reg.startswith('v') and key_reg[1:] in strings:
                        key = strings[key_reg[1:]]
                        
                        # Validate the key
                        if not self._is_valid_extra_name(key):
                            continue
                        
                        # Map Bundle methods to types
                        type_map = {
                            'String': 'string',
                            'Boolean': 'boolean',
                            'Int': 'int',
                            'Long': 'long',
                            'Float': 'float',
                            'Double': 'double',
                            'Byte': 'byte',
                            'Short': 'short',
                            'Char': 'char',
                            'Bundle': 'bundle',
                            'Parcelable': 'parcelable',
                            'Serializable': 'serializable',
                            'StringArray': 'string[]',
                            'IntArray': 'int[]',
                            'StringArrayList': 'ArrayList<String>',
                            'IntegerArrayList': 'ArrayList<Integer>',
                            'ParcelableArrayList': 'ArrayList<Parcelable>',
                        }
                        
                        if method_type in type_map:
                            extras[f"bundle.{key}"] = IntentExtra(
                                name=key,
                                type=f"bundle.{type_map[method_type]}",
                                required=False
                            )
                        
        return extras

    def _analyze_content_provider_operations(self, smali_files: List[Path]) -> Dict[str, Any]:
        """Analyze content provider operations"""
        operations = {
            'uri_patterns': set(),
            'paths': set(),
            'operations': set(),
            'tables': set(),
            'columns': set()
        }
        
        for smali_file in smali_files:
            try:
                content = smali_file.read_text(encoding='utf-8')
            except:
                continue
                
            # Look for URI patterns
            uri_matches = re.findall(r'content://[^"\s]+', content)
            operations['uri_patterns'].update(uri_matches)
            
            # Look for path patterns in strings
            path_matches = re.findall(r'"/[^"\s]+"', content)
            for path in path_matches:
                path = path.strip('"')
                if len(path) > 1 and not path.startswith('/android') and not path.startswith('/system'):
                    operations['paths'].add(path)
            
            # Look for table names (common patterns)
            table_patterns = [
                r'"(\w+_table)"',
                r'"(\w+s)"',  # plural names often indicate tables
                r'TABLE_(\w+)',
                r'"tbl_(\w+)"'
            ]
            for pattern in table_patterns:
                table_matches = re.findall(pattern, content)
                operations['tables'].update(table_matches)
            
            # Look for column names
            column_patterns = [
                r'"(_id)"',
                r'"(\w+_id)"',
                r'"(\w+_name)"',
                r'"(\w+_date)"',
                r'"(\w+_time)"',
                r'COLUMN_(\w+)',
            ]
            for pattern in column_patterns:
                col_matches = re.findall(pattern, content)
                operations['columns'].update(col_matches)
            
            # Look for query/insert/update/delete operations
            for op in ['query', 'insert', 'update', 'delete']:
                if f'ContentResolver;->{op}' in content or f'ContentProvider;->{op}' in content:
                    operations['operations'].add(op)
                    
        return operations

    def analyze_component(self, class_name: str, component_type: str) -> Dict[str, Any]:
        """Analyze component for extras and operations"""
        result = {
            'extras': {},
        }
        
        smali_files = self.find_smali_files(class_name)
        if not smali_files:
            if self.verbose and not self.quiet:
                console.print(f"[yellow]Warning: No smali files found for {class_name}[/yellow]")
            return result
            
        # Determine which methods to analyze based on component type
        methods_to_analyze = {
            'activity': ['onCreate', 'onStart', 'onResume', 'onNewIntent', 'onActivityResult', 
                        'onSaveInstanceState', 'onRestoreInstanceState', 'handleIntent', 'processIntent'],
            'service': ['onCreate', 'onStartCommand', 'onBind', 'onHandleIntent', 'onStart', 
                       'handleIntent', 'processIntent'],
            'receiver': ['onReceive', 'handleIntent', 'processIntent'],
            'provider': ['onCreate', 'query', 'insert', 'update', 'delete', 'getType', 'call',
                        'openFile', 'openAssetFile']
        }.get(component_type, [])
        
        for smali_file in smali_files:
            try:
                content = smali_file.read_text(encoding='utf-8')
                
                # Extract extras from relevant methods
                for method in methods_to_analyze:
                    extras = self._extract_extras_from_method(content, method)
                    result['extras'].update(extras)
                    
            except Exception as e:
                if self.verbose:
                    console.print(f"[red]Error analyzing {smali_file}: {e}[/red]")
                    
        # Special analysis for providers
        if component_type == 'provider':
            provider_ops = self._analyze_content_provider_operations(smali_files)
            result['provider_operations'] = provider_ops
            
        return result

class APKAnalyzer:
    def __init__(self, apk_path: str, verbose: bool = False, quiet: bool = False, cleanup: bool = False):
        self.apk_path = Path(apk_path)
        self.verbose = verbose
        self.quiet = quiet
        self.cleanup = cleanup
        self.decompiled_dir: Optional[Path] = None
        self.smali: Optional[SmaliAnalyzer] = None
        self.success = False
        
        try:
            from androguard.core.bytecodes.apk import APK
            self.apk = APK(str(self.apk_path))
        except ImportError:
            console.print("[bold red]Error:[/] Incorrect androguard version detected!", style="bold red")
            console.print("[yellow]This script requires androguard version 3.3.5 specifically.[/]")
            console.print("[yellow]Newer versions (4.x+) have incompatible API changes.[/]")
            console.print("")
            console.print("[cyan]Fix:[/] pip3 uninstall androguard && pip3 install androguard==3.3.5")
            sys.exit(1)
        except Exception as e:
            console.print(f"[bold red]Error loading APK:[/] {e}", style="bold red")
            sys.exit(1)
            
        self.package = self.apk.get_package()

    def _check_tools(self):
        """Check if required tools are installed"""
        if shutil.which('apktool') is None:
            console.print("[bold red]Error:[/] apktool not found in PATH", style="bold red")
            sys.exit(1)
                
    def decompile(self) -> bool:
        """Decompile APK with apktool"""
        apk_name = self.apk_path.stem
        self.decompiled_dir = self.apk_path.parent / f"{apk_name}_decompiled"
        
        if self.decompiled_dir.exists():
            shutil.rmtree(self.decompiled_dir)
            
        if not self.quiet:
            console.print(f"[bold bright_cyan]APK Components Inspector v{VERSION}[/]")
            console.print(Rule())
            console.print(f"Decompiling {self.apk_path.name}...", style="white")
            
        cmd = ["apktool", "d", "-f", str(self.apk_path), "-o", str(self.decompiled_dir)]
        if not self.verbose:
            cmd.append("-q")
            
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            console.print(f"[bold red]Decompilation failed:[/]\n{result.stderr}", style="red")
            return False
            
        # Verify decompilation
        manifest = self.decompiled_dir / 'AndroidManifest.xml'
        if not manifest.exists():
            console.print("[bold red]Error:[/] AndroidManifest.xml not found after decompilation", style="bold red")
            return False
            
        if not any(self.decompiled_dir.glob('smali*/**/*.smali')):
            console.print("[bold red]Error:[/] No smali files found", style="bold red")
            return False
            
        if not self.quiet:
            console.print(f"✓ Successfully decompiled to {self.decompiled_dir.name}", style="green")
            
        self.smali = SmaliAnalyzer(str(self.decompiled_dir), verbose=self.verbose, quiet=self.quiet)
        return True

    def parse_manifest(self) -> Dict[str, Any]:
        """Parse AndroidManifest.xml"""
        data = {
            'activities': [],
            'services': [],
            'receivers': [],
            'providers': []
        }
        
        manifest_path = self.decompiled_dir / 'AndroidManifest.xml'
        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()
        except ET.ParseError as e:
            console.print(f"[bold red]Error parsing manifest:[/] {e}", style="red")
            return {'error': f'Manifest parse error: {e}'}
            
        # Extract app-level metadata
        app = root.find('.//application')
        if app is None:
            return data
                
        # Component extraction
        component_types = [
            ('activity', 'activities'),
            ('activity-alias', 'activities'),  # Also check activity-alias
            ('service', 'services'),
            ('receiver', 'receivers'),
            ('provider', 'providers')
        ]
        
        for elem_type, data_key in component_types:
            for elem in app.findall(f'.//{elem_type}'):
                comp_info = self._extract_component_info(elem, elem_type.replace('-alias', ''))
                if comp_info and self._is_component_exported(comp_info, elem_type.replace('-alias', '')):
                    data[data_key].append(comp_info)
                    
        return data

    def _extract_component_info(self, elem: ET.Element, comp_type: str) -> Optional[Dict[str, Any]]:
        """Extract component information from manifest"""
        # For activity-alias, use targetActivity
        if elem.tag == 'activity-alias':
            name = elem.get(f'{{{ANDROID}}}targetActivity')
        else:
            name = elem.get(f'{{{ANDROID}}}name')
            
        if not name:
            return None
            
        # Resolve class name
        if name.startswith('.'):
            name = self.package + name
        elif '.' not in name:
            name = f"{self.package}.{name}"
            
        info = {
            'name': name,
            'exported': elem.get(f'{{{ANDROID}}}exported'),
            'permission': elem.get(f'{{{ANDROID}}}permission'),
            'intent_filters': [],
        }
        
        # Extract component-specific attributes
        if comp_type == 'activity':
            info['launchMode'] = elem.get(f'{{{ANDROID}}}launchMode', 'standard')
            info['taskAffinity'] = elem.get(f'{{{ANDROID}}}taskAffinity')
            info['allowTaskReparenting'] = elem.get(f'{{{ANDROID}}}allowTaskReparenting', 'false') == 'true'
            info['clearTaskOnLaunch'] = elem.get(f'{{{ANDROID}}}clearTaskOnLaunch', 'false') == 'true'
            
        elif comp_type == 'service':
            info['process'] = elem.get(f'{{{ANDROID}}}process')
            info['enabled'] = elem.get(f'{{{ANDROID}}}enabled', 'true') == 'true'
            
        elif comp_type == 'receiver':
            info['enabled'] = elem.get(f'{{{ANDROID}}}enabled', 'true') == 'true'
            info['process'] = elem.get(f'{{{ANDROID}}}process')
            
        elif comp_type == 'provider':
            authorities = elem.get(f'{{{ANDROID}}}authorities', '')
            info['authorities'] = [a.strip() for a in authorities.split(';') if a.strip()]
            info['grantUriPermissions'] = elem.get(f'{{{ANDROID}}}grantUriPermissions', 'false') == 'true'
            info['readPermission'] = elem.get(f'{{{ANDROID}}}readPermission')
            info['writePermission'] = elem.get(f'{{{ANDROID}}}writePermission')
            info['multiprocess'] = elem.get(f'{{{ANDROID}}}multiprocess', 'false') == 'true'
            
            # Extract path permissions
            path_perms = []
            for path_perm in elem.findall('.//path-permission'):
                perm_info = {
                    'path': path_perm.get(f'{{{ANDROID}}}path'),
                    'pathPrefix': path_perm.get(f'{{{ANDROID}}}pathPrefix'),
                    'pathPattern': path_perm.get(f'{{{ANDROID}}}pathPattern'),
                }
                # Only add if has actual path info
                if any(perm_info.values()):
                    path_perms.append(perm_info)
                    
            if path_perms:
                info['pathPermissions'] = path_perms
                
            # Extract grant-uri-permission elements
            grant_uris = []
            for grant in elem.findall('.//grant-uri-permission'):
                grant_info = {
                    'path': grant.get(f'{{{ANDROID}}}path'),
                    'pathPrefix': grant.get(f'{{{ANDROID}}}pathPrefix'),
                    'pathPattern': grant.get(f'{{{ANDROID}}}pathPattern'),
                }
                if any(grant_info.values()):
                    grant_uris.append(grant_info)
                    
            if grant_uris:
                info['grantUriPatterns'] = grant_uris
                
        # Extract intent filters
        for intent_filter in elem.findall('.//intent-filter'):
            filter_info = self._extract_intent_filter(intent_filter)
            if filter_info and (filter_info['actions'] or filter_info['data']):  # Only add if has content
                info['intent_filters'].append(filter_info)
                
        return info

    def _extract_intent_filter(self, intent_filter: ET.Element) -> Dict[str, List]:
        """Extract intent filter information"""
        filter_data = {
            'actions': [],
            'categories': [],
            'data': []
        }
        
        # Actions
        for action in intent_filter.findall('.//action'):
            action_name = action.get(f'{{{ANDROID}}}name')
            if action_name:
                filter_data['actions'].append(action_name)
                
        # Categories
        for category in intent_filter.findall('.//category'):
            cat_name = category.get(f'{{{ANDROID}}}name')
            if cat_name:
                filter_data['categories'].append(cat_name)
                
        # Data elements
        for data in intent_filter.findall('.//data'):
            data_info = {}
            attrs = ['scheme', 'host', 'port', 'path', 'pathPrefix', 'pathPattern', 'mimeType']
            for attr in attrs:
                value = data.get(f'{{{ANDROID}}}{attr}')
                if value:
                    data_info[attr] = value
            if data_info:
                filter_data['data'].append(data_info)
                
        return filter_data

    def _is_component_exported(self, comp_info: Dict[str, Any], comp_type: str) -> bool:
        """Determine if component is exported"""
        exported = comp_info.get('exported')
        
        # Explicit exported attribute
        if exported is not None:
            return exported.lower() == 'true'
            
        # Component not enabled
        if not comp_info.get('enabled', True):
            return False
            
        # Has intent filters = exported by default
        if comp_info['intent_filters']:
            # Special case: Main launcher activity (we still want to include these)
            for filter in comp_info['intent_filters']:
                if filter['actions']:  # Has at least one action
                    return True
            return False
            
        # Special cases
        if comp_type == 'provider':
            # Providers need explicit export or grant permissions
            return comp_info.get('grantUriPermissions', False) or bool(comp_info.get('grantUriPatterns'))
            
        return False

    def analyze_components(self, manifest_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze components with Smali inspection"""
        if 'error' in manifest_data:
            return manifest_data
            
        results = {
            'package': self.package,
            'components': {
                'activities': [],
                'services': [],
                'receivers': [],
                'providers': []
            }
        }
        
        # Component type mapping
        comp_types = [
            ('activities', 'activity'),
            ('services', 'service'),
            ('receivers', 'receiver'),
            ('providers', 'provider')
        ]
        
        for data_key, comp_type in comp_types:
            for comp in manifest_data.get(data_key, []):
                if not self.quiet:
                    console.print(f"Analyzing {comp_type}: {comp['name']}", style="cyan")
                    
                # Basic component info
                analysis = {
                    'name': comp['name'],
                    'permission': comp.get('permission'),
                    'intent_filters': comp.get('intent_filters', [])
                }
                
                # Add component-specific attributes
                if comp_type == 'activity':
                    analysis['launchMode'] = comp.get('launchMode', 'standard')
                elif comp_type == 'service':
                    analysis['process'] = comp.get('process')
                elif comp_type == 'provider':
                    analysis['authorities'] = comp.get('authorities', [])
                    analysis['grantUriPermissions'] = comp.get('grantUriPermissions', False)
                    if comp.get('pathPermissions'):
                        analysis['pathPermissions'] = comp['pathPermissions']
                    if comp.get('grantUriPatterns'):
                        analysis['grantUriPatterns'] = comp['grantUriPatterns']
                    
                # Smali analysis
                smali_results = self.smali.analyze_component(comp['name'], comp_type)
                
                # Add extras if found
                if smali_results.get('extras'):
                    analysis['extras'] = smali_results['extras']
                    
                # Add provider operations
                if comp_type == 'provider' and 'provider_operations' in smali_results:
                    analysis['operations'] = smali_results['provider_operations']
                    
                results['components'][data_key].append(analysis)
                
        return results

    def generate_exploits(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate ADB commands for testing"""
        if 'error' in analysis:
            return []
            
        exploits = []
        pkg = self.package
        
        # Activities
        for act in analysis['components']['activities']:
            exploits.extend(self._generate_activity_exploits(act, pkg))
            
        # Services
        for svc in analysis['components']['services']:
            exploits.extend(self._generate_service_exploits(svc, pkg))
            
        # Receivers
        for rcv in analysis['components']['receivers']:
            exploits.extend(self._generate_receiver_exploits(rcv, pkg))
            
        # Providers
        for prv in analysis['components']['providers']:
            exploits.extend(self._generate_provider_exploits(prv, pkg))
            
        return exploits

    def _generate_activity_exploits(self, activity: Dict[str, Any], pkg: str) -> List[Dict[str, Any]]:
        """Generate activity-specific exploits"""
        exploits = []
        name = activity['name']
        
        # Skip if requires permission
        if activity.get('permission'):
            if not self.quiet:
                console.print(f"[yellow]Note: Activity {name} requires permission {activity['permission']}, skipping.[/yellow]")
            return exploits
            
        # Basic launch
        base_cmd = f"adb shell am start -n {pkg}/{name}"
        
        # Check if it has useful intent filters
        has_useful_filters = False
        for filter in activity.get('intent_filters', []):
            if filter.get('actions'):
                has_useful_filters = True
                break
            
        if not has_useful_filters and not activity.get('extras'):
            exploits.append({
                'component': name,
                'command': base_cmd,
                'description': 'Basic activity launch'
            })
        
        # Generate commands for each intent filter
        for filter in activity.get('intent_filters', []):
            for action in filter.get('actions', []):
                cmd = f"{base_cmd} -a {action}"
                
                # Add categories (skip DEFAULT)
                for cat in filter.get('categories', []):
                    if cat != 'android.intent.category.DEFAULT':
                        cmd += f" -c {cat}"
                        
                # Handle data elements properly
                if filter.get('data'):
                    # Try to create commands for each data element
                    for data_elem in filter['data']:
                        data_uri = self._build_data_uri(data_elem)
                        if data_uri:
                            data_cmd = f'{cmd} -d "{data_uri}"'
                            exploits.append({
                                'component': name,
                                'command': data_cmd,
                                'description': f'Launch with action: {action} and data URI'
                            })
                else:
                    # No data element
                    exploits.append({
                        'component': name,
                        'command': cmd,
                        'description': f'Launch with action: {action}'
                    })
                    
        # Generate exploit with extras
        if activity.get('extras'):
            cmd = base_cmd
            extra_desc = []
            
            for extra_name, extra_info in activity['extras'].items():
                extra_cmd, desc = self._generate_extra_flag(extra_name, extra_info)
                if not extra_cmd.startswith('#'):  # Skip complex extras
                    cmd += f" {extra_cmd}"
                    extra_desc.append(desc)
                    
            if extra_desc:  # Only add if we have valid extras
                exploits.append({
                    'component': name,
                    'command': cmd,
                    'description': f'With extras: {", ".join(extra_desc)}'
                })
                
        # Handle special launch modes
        if activity.get('launchMode') not in ['standard', None]:
            launch_mode = activity['launchMode']
            flags = {
                'singleTop': '--activity-single-top',
                'singleTask': '--activity-clear-task',
                'singleInstance': '--activity-clear-task --activity-new-task'
            }
            if launch_mode in flags:
                cmd = f"{base_cmd} {flags[launch_mode]}"
                exploits.append({
                    'component': name,
                    'command': cmd,
                    'description': f'Launch with {launch_mode} mode'
                })
                
        return exploits

    def _generate_service_exploits(self, service: Dict[str, Any], pkg: str) -> List[Dict[str, Any]]:
        """Generate service-specific exploits"""
        exploits = []
        name = service['name']
        
        if service.get('permission'):
            if not self.quiet:
                console.print(f"[yellow]Note: Service {name} requires permission {service['permission']}, skipping.[/yellow]")
            return exploits
            
        base_cmd = f"adb shell am startservice -n {pkg}/{name}"
        
        # Basic start
        if not service.get('intent_filters'):
            exploits.append({
                'component': name,
                'command': base_cmd,
                'description': 'Start service'
            })
        
        # With intent filters
        for filter in service.get('intent_filters', []):
            for action in filter.get('actions', []):
                cmd = f"{base_cmd} -a {action}"
                
                # Handle data if present
                if filter.get('data'):
                    for data_elem in filter['data']:
                        data_uri = self._build_data_uri(data_elem)
                        if data_uri:
                            data_cmd = f'{cmd} -d "{data_uri}"'
                            exploits.append({
                                'component': name,
                                'command': data_cmd,
                                'description': f'Start with action: {action} and data'
                            })
                else:
                    exploits.append({
                        'component': name,
                        'command': cmd,
                        'description': f'Start with action: {action}'
                    })
                
        # Service with extras
        if service.get('extras'):
            cmd = base_cmd
            extra_descs = []
            
            # Add action if available
            if service.get('intent_filters'):
                for filter in service['intent_filters']:
                    if filter.get('actions'):
                        cmd += f" -a {filter['actions'][0]}"
                        break
                        
            for extra_name, extra_info in service['extras'].items():
                extra_cmd, desc = self._generate_extra_flag(extra_name, extra_info)
                if not extra_cmd.startswith('#'):
                    cmd += f" {extra_cmd}"
                    extra_descs.append(desc)
                    
            if extra_descs:
                exploits.append({
                    'component': name,
                    'command': cmd,
                    'description': f'Start with extras: {", ".join(extra_descs)}'
                })
                
        # Foreground service (API 26+)
        if not service.get('intent_filters'):
            exploits.append({
                'component': name,
                'command': f"adb shell am start-foreground-service -n {pkg}/{name}",
                'description': 'Start as foreground service (API 26+)'
            })
                
        return exploits

    def _generate_receiver_exploits(self, receiver: Dict[str, Any], pkg: str) -> List[Dict[str, Any]]:
        """Generate broadcast receiver exploits"""
        exploits = []
        name = receiver['name']
        
        if receiver.get('permission'):
            if not self.quiet:
                console.print(f"[yellow]Note: Receiver {name} requires permission {receiver['permission']}, skipping.[/yellow]")
            return exploits
            
        # Need intent filters for broadcasts
        if not receiver.get('intent_filters'):
            # Try explicit component broadcast
            exploits.append({
                'component': name,
                'command': f"adb shell am broadcast -n {pkg}/{name}",
                'description': 'Explicit broadcast to component'
            })
            
        for filter in receiver.get('intent_filters', []):
            for action in filter.get('actions', []):
                cmd = f"adb shell am broadcast -a {action}"
                
                # Add component if it's a custom action
                if self._is_custom_action(action):
                    cmd += f" -n {pkg}/{name}"
                    
                # Handle data elements
                if filter.get('data'):
                    for data_elem in filter['data']:
                        data_uri = self._build_data_uri(data_elem)
                        if data_uri:
                            data_cmd = f'{cmd} -d "{data_uri}"'
                            exploits.append({
                                'component': name,
                                'command': data_cmd,
                                'description': f'Broadcast: {action} with data'
                            })
                else:
                    exploits.append({
                        'component': name,
                        'command': cmd,
                        'description': f'Broadcast: {action}'
                    })
                    
        # Receiver with extras
        if receiver.get('extras'):
            # Use the first available action or explicit component
            if receiver.get('intent_filters'):
                for filter in receiver['intent_filters']:
                    if filter.get('actions'):
                        cmd = f"adb shell am broadcast -a {filter['actions'][0]}"
                        if self._is_custom_action(filter['actions'][0]):
                            cmd += f" -n {pkg}/{name}"
                        break
                else:
                    cmd = f"adb shell am broadcast -n {pkg}/{name}"
            else:
                cmd = f"adb shell am broadcast -n {pkg}/{name}"
                
            extra_descs = []
            for extra_name, extra_info in receiver['extras'].items():
                extra_cmd, desc = self._generate_extra_flag(extra_name, extra_info)
                if not extra_cmd.startswith('#'):
                    cmd += f" {extra_cmd}"
                    extra_descs.append(desc)
                    
            if extra_descs:
                exploits.append({
                    'component': name,
                    'command': cmd,
                    'description': f'Broadcast with extras: {", ".join(extra_descs)}'
                })
                
        return exploits

    def _generate_provider_exploits(self, provider: Dict[str, Any], pkg: str) -> List[Dict[str, Any]]:
        """Generate content provider exploits"""
        exploits = []
        name = provider['name']
        
        if provider.get('permission'):
            if not self.quiet:
                console.print(f"[yellow]Note: Provider {name} requires permission {provider['permission']}, skipping.[/yellow]")
            return exploits
            
        for authority in provider.get('authorities', []):
            base_uri = f"content://{authority}"
            
            # Generate paths to test
            paths_to_test = []
            
            # Add paths from manifest
            if 'pathPermissions' in provider:
                for path_perm in provider['pathPermissions']:
                    if path_perm.get('path'):
                        paths_to_test.append(path_perm['path'])
                    if path_perm.get('pathPrefix'):
                        paths_to_test.append(f"{path_perm['pathPrefix']}test")
                    if path_perm.get('pathPattern'):
                        # Convert pattern to example
                        pattern = path_perm['pathPattern']
                        example = pattern.replace('.*', 'test').replace('\\d+', '123').replace('\\', '')
                        paths_to_test.append(example)
                        
            # Add paths from grant URI patterns
            if 'grantUriPatterns' in provider:
                for grant in provider['grantUriPatterns']:
                    if grant.get('path'):
                        paths_to_test.append(grant['path'])
                    if grant.get('pathPrefix'):
                        paths_to_test.append(f"{grant['pathPrefix']}test")
                        
            # Add paths from smali analysis
            if 'operations' in provider:
                ops = provider['operations']
                if 'paths' in ops:
                    paths_to_test.extend(ops['paths'])
                    
                # Add table names as potential paths
                if 'tables' in ops:
                    for table in ops['tables']:
                        paths_to_test.append(f"/{table}")
                        
            # Add common paths if no specific paths found
            if not paths_to_test:
                paths_to_test = ['']  # Just the base URI
                
                # If we found operations, add common patterns
                if 'operations' in provider and provider['operations'].get('operations'):
                    paths_to_test.extend(['/*', '/test', '/1'])
                    
            # Remove duplicates and empty paths
            paths_to_test = list(set(p for p in paths_to_test if p is not None))
            
            # Generate commands for each path
            for path in paths_to_test:
                uri = f"{base_uri}{path}"
                
                # Basic query
                exploits.append({
                    'component': name,
                    'command': f'adb shell content query --uri "{uri}"',
                    'description': f'Query: {uri}'
                })
                
                # Query with columns from smali
                if 'operations' in provider and 'columns' in provider['operations']:
                    columns = list(provider['operations']['columns'])[:5]  # Limit to 5 columns
                    if columns:
                        col_list = ':'.join(columns)
                        exploits.append({
                            'component': name,
                            'command': f'adb shell content query --uri "{uri}" --projection "{col_list}"',
                            'description': f'Query specific columns: {uri}'
                        })
                
                # SQL injection test
                exploits.append({
                    'component': name,
                    'command': f'adb shell content query --uri "{uri}" --where "1=1--"',
                    'description': f'SQL injection test: {uri}'
                })
                
                # If we know it supports other operations from smali
                if 'operations' in provider:
                    ops = provider['operations'].get('operations', set())
                    
                    if 'insert' in ops:
                        exploits.append({
                            'component': name,
                            'command': f'adb shell content insert --uri "{uri}" --bind name:s:test --bind value:s:data',
                            'description': f'Insert test: {uri}'
                        })
                        
                    if 'update' in ops:
                        exploits.append({
                            'component': name,
                            'command': f'adb shell content update --uri "{uri}" --bind value:s:newdata --where "name=\'test\'"',
                            'description': f'Update test: {uri}'
                        })
                        
                    if 'delete' in ops:
                        exploits.append({
                            'component': name,
                            'command': f'adb shell content delete --uri "{uri}" --where "name=\'test\'"',
                            'description': f'Delete test: {uri}'
                        })
                        
            # File operations
            if provider.get('grantUriPermissions') or provider.get('grantUriPatterns'):
                uri = f"{base_uri}/test.txt"
                exploits.append({
                    'component': name,
                    'command': f'adb shell content read --uri "{uri}"',
                    'description': f'Read file: {uri}'
                })
                exploits.append({
                    'component': name,
                    'command': f'echo "test data" | adb shell content write --uri "{uri}"',
                    'description': f'Write file: {uri}'
                })
                        
        return exploits

    def _build_data_uri(self, data_elem: Dict[str, str]) -> str:
        """Build proper data URI from manifest data element"""
        scheme = data_elem.get('scheme', '')
        host = data_elem.get('host', '')
        port = data_elem.get('port', '')
        path = data_elem.get('path', '')
        path_prefix = data_elem.get('pathPrefix', '')
        path_pattern = data_elem.get('pathPattern', '')
        mime_type = data_elem.get('mimeType', '')
        
        # Build URI based on what's available
        if scheme and host:
            uri = f"{scheme}://{host}"
            if port:
                uri += f":{port}"
            # Use the most specific path
            if path:
                uri += path
            elif path_prefix:
                uri += f"{path_prefix}test"
            elif path_pattern:
                # Convert pattern to example
                example = path_pattern.replace('.*', 'test').replace('\\d+', '123').replace('\\', '')
                uri += example
            return uri
        elif scheme:
            # Some intents only have scheme (like tel:, mailto:, etc.)
            examples = {
                'tel': 'tel:+1234567890',
                'sms': 'sms:+1234567890',
                'smsto': 'smsto:+1234567890',
                'mailto': 'mailto:test@example.com',
                'geo': 'geo:0,0?q=test',
                'http': 'http://example.com',
                'https': 'https://example.com',
                'file': 'file:///sdcard/test.txt',
                'content': 'content://com.example.provider/test',
            }
            return examples.get(scheme, f"{scheme}://test")
        elif mime_type:
            # For mime types without scheme
            if '/' in mime_type:
                ext = mime_type.split('/')[-1]
                if ext in ['jpeg', 'jpg', 'png', 'gif']:
                    return f"file:///sdcard/test.{ext}"
                elif ext == 'plain':
                    return "file:///sdcard/test.txt"
                else:
                    return f"file:///sdcard/test.{ext}"
            return "file:///sdcard/test"
        
        return ""

    def _generate_extra_flag(self, name: str, extra: IntentExtra) -> Tuple[str, str]:
        """Generate appropriate extra flag for ADB command"""
        # Clean up bundle prefix if present
        display_name = name.replace('bundle.', '')
        
        type_map = {
            'string': ('--es', '"test_string"'),
            'boolean': ('--ez', 'true'),
            'int': ('--ei', '123'),
            'long': ('--el', '1234567890'),
            'float': ('--ef', '1.23'),
            'double': ('--ed', '1.234567'),
            'byte': ('--ei', '127'),  # byte uses int flag
            'short': ('--ei', '32767'),  # short uses int flag
            'char': ('--ei', '65'),  # char uses int flag (ASCII 'A')
            'string[]': ('--esa', 'item1,item2,item3'),
            'int[]': ('--eia', '1,2,3'),
            'byte[]': ('--eia', '1,2,3'),
            'char[]': ('--eia', '65,66,67'),  # ABC
            'float[]': ('--efa', '1.1,2.2,3.3'),
            'double[]': ('--eda', '1.1,2.2,3.3'),
            'long[]': ('--ela', '100,200,300'),
            'short[]': ('--eia', '100,200,300'),
            'boolean[]': ('--eza', 'true,false,true'),
            'ArrayList<String>': ('--esal', 'item1,item2,item3'),
            'ArrayList<Integer>': ('--eial', '1,2,3'),
        }
        
        # Handle bundle extras
        if extra.type.startswith('bundle.'):
            actual_type = extra.type.replace('bundle.', '')
            if actual_type in type_map:
                flag, value = type_map[actual_type]
                # Use default value if provided
                if extra.default_value:
                    value = extra.default_value
                return f"{flag} {display_name} {value}", f"{display_name}({actual_type})"
                
        if extra.type in type_map:
            flag, value = type_map[extra.type]
            # Use default value if provided
            if extra.default_value:
                value = extra.default_value
            return f"{flag} {display_name} {value}", f"{display_name}({extra.type})"
        else:
            # For complex types that can't be passed via ADB easily
            return f"# Complex extra: {display_name} ({extra.type})", f"{display_name}({extra.type})[manual]"

    def _is_custom_action(self, action: str) -> bool:
        """Check if action is custom (not Android standard)"""
        standard_prefixes = [
            'android.intent.action.',
            'android.app.action.',
            'android.bluetooth.',
            'android.net.',
            'android.nfc.',
            'android.provider.',
            'android.settings.',
            'android.media.',
            'android.service.',
            'android.speech.',
            'android.telephony.',
            'android.text.',
            'android.view.',
            'android.webkit.',
            'android.widget.',
            'com.android.',
            'com.google.android.',
        ]
        return not any(action.startswith(prefix) for prefix in standard_prefixes)

    def analyze(self) -> Dict[str, Any]:
        """Main analysis pipeline"""
        self._check_tools()
        
        if not self.decompile():
            return {'error': 'Decompilation failed'}
            
        if not self.quiet:
            console.print("Parsing AndroidManifest.xml...", style="white")
        manifest = self.parse_manifest()
        
        if 'error' in manifest:
            return manifest
            
        if not self.quiet:
            console.print("Analyzing components...", style="white")
        analysis = self.analyze_components(manifest)
        
        if 'error' in analysis:
            return analysis
            
        if not self.quiet:
            console.print("Generating exploits...", style="white")
        exploits = self.generate_exploits(analysis)
        
        analysis['exploits'] = exploits
        self.success = True
        
        return analysis

    def print_results(self, results: Dict[str, Any]):
        """Pretty print analysis results"""
        console.print(Rule(style="bright_cyan"))
        console.print(f"[bold bright_cyan]Package:[/] {results['package']}")
        
        # Component summary
        total = sum(len(v) for v in results['components'].values())
        console.print(f"[bold yellow]Exported Components:[/] {total}")
        
        if total == 0:
            console.print("[yellow]⚠ No exported components found[/]")
            return
            
        console.print(Rule(style="bright_cyan"))
        
        # Group exploits by component
        component_exploits = {}
        for exploit in results.get('exploits', []):
            comp = exploit['component']
            if comp not in component_exploits:
                component_exploits[comp] = []
            component_exploits[comp].append(exploit)
            
        # Print table of components and descriptions
        table = Table(show_header=True, header_style="bold bright_cyan", box=None)
        table.add_column("Component", style="yellow", no_wrap=True)
        table.add_column("Type", style="cyan")
        table.add_column("Exploits", style="white")
        
        # Fixed component type display
        type_names = {
            'activities': 'activity',
            'services': 'service', 
            'receivers': 'receiver',
            'providers': 'provider'
        }
        
        for comp_type, components in results['components'].items():
            for comp in components:
                name = comp['name']
                short_name = name.split('.')[-1]
                exploit_count = len(component_exploits.get(name, []))
                
                table.add_row(
                    short_name,
                    type_names.get(comp_type, comp_type),
                    str(exploit_count)
                )
                
        console.print(table)
        
        # Print commands
        console.print(Rule(style="bright_cyan"))
        console.print(Text("ADB Commands:", style="bold bright_cyan"))
        
        for comp_name, exploits in component_exploits.items():
            short_name = comp_name.split('.')[-1]
            console.print(f"\n[yellow]{short_name}:[/]")
            
            for exploit in exploits:
                console.print(f"  [cyan]# {exploit['description']}[/]")
                console.print(f"  {exploit['command']}")

    def save_results(self, results: Dict[str, Any], output_path: str):
        """Save results to JSON file"""
        Path(output_path).write_text(json.dumps(results, indent=2))
        if not self.quiet:
            console.print(f"\n[green]✓ Results saved to:[/] {output_path}")

    def cleanup_dir(self):
        """Clean up decompiled directory"""
        if self.cleanup and self.success and self.decompiled_dir and self.decompiled_dir.exists():
            shutil.rmtree(self.decompiled_dir)
            if not self.quiet:
                console.print("[green]✓ Cleaned up temporary files[/]")


# ==================== FUNCIONES AUXILIARES ====================
def run_command(cmd: List[str], tool: str = 'adb') -> str:
    """Ejecuta un comando ADB o Fastboot y devuelve la salida."""
    try:
        tool_path = TOOL_PATHS.get(tool)
        if not tool_path:
            raise ValueError(f"Herramienta no configurada: {tool}")
            
        result = subprocess.run(
            [tool_path] + cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='replace'
        )
        return result.stdout.strip()
    except Exception as e:
        print(f"[❌] Error ejecutando {' '.join(cmd)}: {e}")
        return ""

def run_adb(cmd: List[str]) -> str:
    """Ejecuta un comando ADB con el dispositivo seleccionado."""
    full_cmd = ADB_COMMANDS.get(cmd[0], []) + cmd[1:] if cmd and isinstance(cmd, list) else cmd
    if selected_device:
        full_cmd = ['-s', selected_device] + full_cmd
    return run_command(full_cmd, 'adb')

def run_fastboot(cmd: List[str]) -> str:
    """Ejecuta un comando Fastboot."""
    full_cmd = FASTBOOT_COMMANDS.get(cmd[0], []) + cmd[1:] if cmd and isinstance(cmd, list) else cmd
    return run_command(full_cmd, 'fastboot')

def validate_device() -> bool:
    """Verifica que haya un dispositivo seleccionado."""
    if not selected_device:
        print("[⚠️] No hay dispositivo seleccionado.")
        return False
    return True

# ==================== GESTIÓN DE DISPOSITIVOS ====================
def list_devices() -> List[Tuple[int, str, str]]:
    """Lista los dispositivos conectados con su arquitectura."""
    output = run_adb(ADB_COMMANDS['devices'])
    devices = []
    
    for i, line in enumerate(output.strip().splitlines()[1:]):
        if "device" in line:
            device_id = line.split()[0]
            arch = run_adb(SYSTEM_COMMANDS['shell'] + ["getprop", "ro.product.cpu.abi"])
            devices.append((i + 1, device_id, arch.strip()))
    
    return devices

def select_device(devices: List[Tuple[int, str, str]]) -> None:
    """Permite seleccionar un dispositivo de la lista."""
    global selected_device
    
    print("\n[📱] Dispositivos disponibles:")
    for idx, dev, arch in devices:
        print(f"  {idx}. {dev} [{arch}]")
    
    choice = input("\n[🎯] Selecciona dispositivo por número: ").strip()
    
    if choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(devices):
            selected_device = devices[idx][1]
            print(f"[✅] Dispositivo seleccionado: {selected_device}")
        else:
            print("[❌] Número fuera de rango.")
    else:
        print("[❌] Entrada inválida.")

def reboot_device(mode: str) -> None:
    """Reinicia el dispositivo en el modo especificado."""
    if validate_device():
        run_adb(ADB_COMMANDS['reboot'] + [mode])
        print(f"[🔄] Reiniciando en modo {mode}...")

def disconnect_wifi() -> None:
    """Desconecta dispositivos ADB por WiFi."""
    run_adb(ADB_COMMANDS['disconnect'])
    print("[🔌] Dispositivos desconectados vía WiFi.")

# ==================== GESTIÓN DE APLICACIONES ====================
def list_apps() -> List[str]:
    """Lista los paquetes de aplicaciones instaladas."""
    if not validate_device():
        return []
    
    output = run_adb(SYSTEM_COMMANDS['pm_list'])
    apps = [line.replace("package:", "").strip() for line in output.splitlines()]
    
    for i, pkg in enumerate(apps, 1):
        print(f"  {i}. {pkg}")
    
    return apps

def get_apk_path(package: str) -> str:
    """Obtiene la ruta del APK de un paquete."""
    output = run_adb(SYSTEM_COMMANDS['pm_path'] + [package])
    path = output.strip().replace("package:", "")
    print(f"[📦] Ruta de APK: {path}")
    return path

def pull_apk(package: str) -> None:
    """Extrae el APK de un paquete."""
    apk_path = get_apk_path(package)
    if apk_path:
        run_adb(ADB_COMMANDS['pull'] + [apk_path])
        print(f"[📥] APK extraída: {apk_path.split('/')[-1]}")

def install_apk(apk_file: str) -> None:
    """Instala un APK en el dispositivo."""
    run_adb(ADB_COMMANDS['install'] + [apk_file])
    print("[✅] APK instalada.")

def uninstall_app(package: str) -> None:
    """Desinstala una aplicación."""
    run_adb(ADB_COMMANDS['uninstall'] + [package])
    print("[🗑️] Aplicación desinstalada.")

def clear_app_data(package: str) -> None:
    """Borra los datos de una aplicación."""
    run_adb(SYSTEM_COMMANDS['pm_clear'] + [package])
    print(f"[🧹] Datos de {package} borrados.")

def force_stop_app(package: str) -> None:
    """Fuerza el cierre de una aplicación."""
    run_adb(SYSTEM_COMMANDS['am_force_stop'] + [package])
    print(f"[🛑] Aplicación {package} detenida.")

def launch_app(package: str) -> None:
    """Lanza una aplicación."""
    run_adb(SYSTEM_COMMANDS['monkey'] + [package, "1"])
    print(f"[🚀] Aplicación {package} lanzada.")

def get_app_info(package: str) -> None:
    """Muestra información detallada de una aplicación."""
    output = run_adb(SYSTEM_COMMANDS['dumpsys'] + ["package", package])
    print(output)

def check_backup_enabled(package: str) -> None:
    """Verifica si una aplicación permite backup."""
    output = run_adb(SYSTEM_COMMANDS['pm_list'] + ["-f", package])
    if not output:
        print("[❌] No se encontró la aplicación.")
        return
    
    try:
        apk_path = output.split(":")[1].split("=")[0]
        manifest = run_adb(SYSTEM_COMMANDS['shell'] + [f"aapt dump badging {apk_path} | grep 'allowBackup'"])
        
        if "allowBackup=true" in manifest:
            print(f"[🔍] La aplicación {package} permite backup.")
        elif "allowBackup=false" in manifest:
            print(f"[🔒] La aplicación {package} NO permite backup.")
        else:
            print(f"[❓] No se pudo determinar si permite backup.")
    except Exception as e:
        print(f"[❌] Error obteniendo información de backup: {e}")

# ==================== MANIPULACIÓN DE APKs ====================
def sign_apk(apk_file: str) -> None:
    """Firma un APK usando uber-apk-signer."""
    os.system(f"{TOOL_PATHS['uber_apk_signer']} --apks {apk_file}")

def decompile_apk(apk_file: str) -> None:
    """Descompila un APK usando apktool."""
    os.system(f"{TOOL_PATHS['apktool']} d {apk_file}")

def recompile_apk(folder: str) -> None:
    """Recompila una carpeta usando apktool."""
    os.system(f"{TOOL_PATHS['apktool']} b {folder}")

# ==================== SISTEMA Y DEBUGGING ====================
def check_battery() -> None:
    """Muestra información de la batería."""
    output = run_adb(SYSTEM_COMMANDS['dumpsys'] + ["battery"])
    print(output)

def start_shell() -> None:
    """Inicia una shell ADB interactiva."""
    if validate_device():
        subprocess.run([TOOL_PATHS['adb'], "-s", selected_device] + SYSTEM_COMMANDS['shell'])

def show_logcat() -> None:
    """Muestra el logcat en una nueva ventana."""
    if validate_device():
        cmd = f'start cmd /k "{TOOL_PATHS["adb"]} -s {selected_device} logcat"'
        os.system(cmd)
        print("[🔌] Logcat iniciado en nueva ventana.")

def filtered_logcat() -> None:
    """Muestra logcat con filtros personalizados."""
    if not validate_device():
        return
    
    tag = input("Introduce el tag (ej: ActivityManager) o deja vacío para todos: ").strip()
    priority = input("Nivel de prioridad (V/D/I/W/E/F/S): ").strip().upper() or "V"
    
    cmd = [TOOL_PATHS['adb'], "-s", selected_device] + ADB_COMMANDS['logcat']
    if tag:
        cmd += [f"{tag}:{priority}", "*:S"]
    
    try:
        print(f"[🔍] Iniciando logcat filtrado ({tag}:{priority})...")
        subprocess.Popen(cmd)
    except Exception as e:
        print(f"[❌] Error iniciando logcat: {e}")

def disable_verify_apps() -> None:
    """Deshabilita la verificación de aplicaciones."""
    run_adb(SYSTEM_COMMANDS['settings'])
    print("[🔓] Verificación de instalaciones deshabilitada.")

# ==================== SEGURIDAD ====================
def check_root() -> None:
    """Verifica si el dispositivo tiene root."""
    try:
        output = run_adb(SYSTEM_COMMANDS['shell'] + ["su", "-c", "id"])
        print("[✅] El dispositivo tiene permisos root." if "uid=0" in output else "[❌] El dispositivo NO tiene permisos root.")
    except Exception as e:
        print(f"[❌] Error verificando root: {e}")

def disable_selinux() -> None:
    """Deshabilita SELinux temporalmente."""
    try:
        run_adb(SYSTEM_COMMANDS['shell'] + ["su", "-c", "setenforce 0"])
        print("[🔓] SELinux desactivado.")
    except Exception as e:
        print(f"[❌] No se pudo deshabilitar SELinux: {e}")

def dump_ram(file_path: str = "/sdcard/ramdump.bin") -> None:
    """Vuelca la memoria RAM a un archivo."""
    try:
        run_adb(SYSTEM_COMMANDS['shell'] + ["su", "-c", f"dd if=/dev/mem of={file_path} bs=1024"])
        print(f"[💾] Memoria volcada a {file_path}")
    except Exception as e:
        print(f"[❌] Error al volcar memoria: {e}")

# ==================== FASTBOOT ====================
def list_fastboot_devices() -> None:
    """Lista dispositivos en modo fastboot."""
    output = run_fastboot(FASTBOOT_COMMANDS['devices'])
    print("[📱] Dispositivos en modo fastboot:" if output.strip() else "[⚠️] No hay dispositivos en modo fastboot.")
    print(output)

def get_fastboot_info() -> None:
    """Muestra información del dispositivo en fastboot."""
    output = run_fastboot(FASTBOOT_COMMANDS['getvar'])
    print("[🔍] Información del dispositivo en modo fastboot:")
    print(output)

def unlock_bootloader() -> None:
    """Desbloquea el bootloader."""
    if input("[❗] Esta acción borrará todos los datos. ¿Continuar? (s/n): ").strip().lower() == 's':
        run_fastboot(FASTBOOT_COMMANDS['oem_unlock'])
        print("[🔓] Bootloader desbloqueado.")

def lock_bootloader() -> None:
    """Bloquea el bootloader."""
    if input("[❗] Esta acción bloqueará el bootloader. ¿Continuar? (s/n): ").strip().lower() == 's':
        run_fastboot(FASTBOOT_COMMANDS['oem_lock'])
        print("[🔒] Bootloader bloqueado.")

def erase_userdata() -> None:
    """Borra la partición userdata."""
    if input("[❗] Esta acción borrará todos los datos del usuario. ¿Continuar? (s/n): ").strip().lower() == 's':
        run_fastboot(FASTBOOT_COMMANDS['erase'] + ["userdata"])
        print("[🗑️] Partición userdata borrada.")

def flash_recovery(image_path: str) -> None:
    """Flashea una imagen de recovery."""
    run_fastboot(FASTBOOT_COMMANDS['flash'] + ["recovery", image_path])
    print(f"[⚡] Recovery flasheado desde: {image_path}")

def enter_edl_mode() -> None:
    """Pone el dispositivo en modo EDL."""
    run_fastboot(FASTBOOT_COMMANDS['edl'])
    print("[🔌] Enviando dispositivo a modo EDL...")

def reboot_fastboot() -> None:
    """Reinicia el dispositivo desde fastboot."""
    run_fastboot(FASTBOOT_COMMANDS['reboot'])
    print("[🔄] Reiniciando dispositivo...")

# ==================== HOOKS Y MONITOREO ====================
def get_foreground_app() -> Optional[str]:
    """Obtiene el paquete de la aplicación en primer plano."""
    output = run_adb(SYSTEM_COMMANDS['dumpsys'] + ["window", "windows"])
    match = REGEX_PATTERNS['foreground_app'].search(output)
    return match.group(1) if match else None

def inject_frida_hook() -> None:
    """Inyecta un script Frida en la aplicación en primer plano."""
    app = get_foreground_app()
    if not app:
        print("[❌] No se pudo detectar la app activa.")
        return
    
    print(f"[🎯] App activa: {app}")
    print(f"[🧪] Inyectando hook con Frida...")

    try:
        subprocess.Popen(
            [TOOL_PATHS['frida'], "-U", "--no-pause", "-n", app, "-l", CONFIG_FILES['frida_hook']],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        print(f"[✅] Hook inyectado en {app}")
    except Exception as e:
        print(f"[❌] Error al inyectar: {e}")

def monitor_camera_logcat() -> None:
    """Monitorea logcat para detectar uso de cámara."""
    print("[🔍] Escuchando logcat por uso de cámara...")
    try:
        process = subprocess.Popen(
            [TOOL_PATHS['adb'], "-s", selected_device] + ADB_COMMANDS['logcat'],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding='utf-8',
            errors='replace'
        )

        for line in process.stdout:
            if REGEX_PATTERNS['camera'].search(line):
                print(f"[🎥] {datetime.datetime.now().strftime('%H:%M:%S')} {line.strip()}")
    except Exception as e:
        print(f"[❌] Error leyendo logcat: {e}")

# ==================== ANÁLISIS DE APKs ====================
def search_files_for_patterns(folder: str, patterns: List[Pattern]) -> List[Dict[str, Any]]:
    """Busca patrones en archivos dentro de una carpeta."""
    results = []
    for root, _, files in os.walk(folder):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line_num, line in enumerate(f, 1):
                        for pattern in patterns:
                            if pattern.search(line):
                                results.append({
                                    'file': file_path,
                                    'line': line_num,
                                    'content': line.strip()
                                })
            except Exception as e:
                print(f"Error leyendo {file_path}: {e}")
    return results

def analyze_apk_for_urls() -> None:
    """Analiza un APK en busca de URLs."""
    apps = list_apps()
    if not apps:
        print("[❌] No se encontraron apps.")
        return

    try:
        idx = int(input(f"\n[🔍] Selecciona el número de la app para analizar: ").strip()) - 1
        if idx < 0 or idx >= len(apps):
            print("[❌] Selección inválida.")
            return
    except ValueError:
        print("[❌] Entrada inválida.")
        return

    package = apps[idx]
    print(f"[📦] Analizando paquete: {package}")

    # Extraer APK
    apk_path = get_apk_path(package)
    if not apk_path:
        return

    local_apk = f"{package.replace('.', '_')}.apk"
    run_adb(ADB_COMMANDS['pull'] + [apk_path, local_apk])
    print(f"[📥] APK guardado localmente como: {local_apk}")

    # Decompilar
    output_folder = f"{package.replace('.', '_')}_decoded"
    os.system(f"{TOOL_PATHS['apktool']} d -f {local_apk} -o {output_folder}")
    print(f"[🔧] APK decompilado en: {output_folder}")

    # Buscar URLs
    found = search_files_for_patterns(output_folder, REGEX_PATTERNS['urls'])
    
    if found:
        print(f"\n[✅] Se encontraron {len(found)} coincidencias:\n")
        for item in found:
            print(f"{item['file']} (línea {item['line']}): {item['content']}")

        # Guardar resultados
        with open(CONFIG_FILES['url_results']['text'], "w", encoding="utf-8") as txt_file:
            for item in found:
                txt_file.write(f"{item['file']} (línea {item['line']}): {item['content']}\n")

        with open(CONFIG_FILES['url_results']['json'], "w", encoding="utf-8") as json_file:
            json.dump(found, json_file, ensure_ascii=False, indent=2)

        print(f"\n[💾] Resultados guardados en '{CONFIG_FILES['url_results']['text']}' y '{CONFIG_FILES['url_results']['json']}'.")
    else:
        print("[🔍] No se encontraron URLs en los archivos decompilados.")
def analyze_apk_components():
    """Usa APK Components Inspector para analizar un APK desde el toolkit."""
    apps = list_apps()
    if not apps:
        return

    try:
        idx = int(input(f"\n[🔍] Selecciona número de la app para analizar: ").strip()) - 1
        if idx < 0 or idx >= len(apps):
            print("[❌] Selección inválida.")
            return
    except ValueError:
        print("[❌] Entrada inválida.")
        return

    package = apps[idx]
    print(f"[📦] Analizando paquete: {package}")

    apk_path = get_apk_path(package)
    if not apk_path:
        return

    local_apk = f"{package.replace('.', '_')}.apk"
    run_adb(ADB_COMMANDS['pull'] + [apk_path, local_apk])
    print(f"[📥] APK descargado: {local_apk}")

    from apk_components_inspector import APKAnalyzer  # Si ya pegaste el código, omite este import

    analyzer = APKAnalyzer(apk_path=local_apk, verbose=True, quiet=False, cleanup=True)
    results = analyzer.analyze()

    if 'error' in results:
        print(f"[❌] Error: {results['error']}")
    else:
        analyzer.print_results(results)

# ==================== MENÚ PRINCIPAL ====================
def main_menu() -> None:
    """Muestra el menú principal y maneja la interacción del usuario."""
    MENU_SECTIONS = [
        {
            "title": "🔹 DISPOSITIVOS",
            "items": [
                ("Listar dispositivos", lambda: select_device(list_devices())),
                ("Reiniciar en Recovery", lambda: reboot_device("recovery")),
                ("Reiniciar en Fastboot", lambda: reboot_device("bootloader")),
                ("Desconectar WiFi", disconnect_wifi),
            ]
        },
        {
            "title": "📦 APLICACIONES",
            "items": [
                ("Listar aplicaciones", list_apps),
                ("Ver ruta de APK", lambda: get_apk_path(input('Paquete: ').strip())),
                ("Extraer APK", lambda: pull_apk(input('Paquete: ').strip())),
                ("Desinstalar app", lambda: uninstall_app(input('Paquete: ').strip())),
                ("Limpiar datos app", lambda: clear_app_data(input('Paquete: ').strip())),
                ("Forzar detención app", lambda: force_stop_app(input('Paquete: ').strip())),
                ("Lanzar app", lambda: launch_app(input('Paquete: ').strip())),
                ("Info detallada app", lambda: get_app_info(input('Paquete: ').strip())),
                ("¿Permite backup?", lambda: check_backup_enabled(input('Paquete: ').strip())),
            ]
        },
        {
            "title": "🧱 MANIPULACIÓN DE APK",
            "items": [
                ("Firmar APK", lambda: sign_apk(input('Ruta del APK: ').strip())),
                ("Decompilar APK", lambda: decompile_apk(input('Ruta del APK: ').strip())),
                ("Recompilar carpeta", lambda: recompile_apk(input('Carpeta: ').strip())),
                ("Instalar APK", lambda: install_apk(input('Ruta del APK: ').strip())),
            ]
        },
        {
            "title": "🛡️ SEGURIDAD & ROOT",
            "items": [
                ("Verificar root", check_root),
                ("Deshabilitar SELinux", disable_selinux),
                ("Volcar memoria RAM", lambda: dump_ram(input('Ruta destino (opcional): ').strip() or "/sdcard/ramdump.bin")),
            ]
        },
        {
            "title": "🔧 SISTEMA & DEBUG",
            "items": [
                ("Mostrar estado de batería", check_battery),
                ("Logcat completo", show_logcat),
                ("Logcat con filtro", filtered_logcat),
                ("Acceder a shell", start_shell),
                ("Deshabilitar verificación de apps", disable_verify_apps),
            ]
        },
        {
            "title": "⚙️ FASTBOOT",
            "items": [
                ("Listar dispositivos Fastboot", list_fastboot_devices),
                ("Obtener info del dispositivo", get_fastboot_info),
                ("Desbloquear Bootloader", unlock_bootloader),
                ("Bloquear Bootloader", lock_bootloader),
                ("Borrar partición userdata", erase_userdata),
                ("Flashear recovery", lambda: flash_recovery(input('Ruta de imagen recovery: ').strip())),
                ("Entrar en modo EDL", enter_edl_mode),
                ("Reiniciar desde Fastboot", reboot_fastboot),
            ]
        },
        {
            "title": "📷 CÁMARA & HOOKS",
            "items": [
                ("Escuchar uso de cámara (logcat)", lambda: threading.Thread(target=monitor_camera_logcat, daemon=True).start()),
                ("Inyectar hook Frida en app activa", inject_frida_hook),
            ]
        },
      {
    "title": "🔎 ANÁLISIS DE APK",
    "items": [
        ("Extraer y buscar URLs en APK", analyze_apk_for_urls),
        ("Analizar componentes del APK (Inspector)", analyze_apk_components)  # NUEVA OPCIÓN
    ]
},

    ]

    while True:
        print("\n\n[📱] === TOOLKIT ANDROID (ADB + FASTBOOT) ===")
        print(f"[🔌] Dispositivo seleccionado: {selected_device or 'Ninguno'}")
        
        option_index = 1
        section_map = []

        # Mostrar menú
        for section in MENU_SECTIONS:
            print(f"\n{section['title']}")
            for item in section["items"]:
                print(f" {option_index}. {item[0]}")
                section_map.append(item[1])
                option_index += 1

        print("\n🚪 SALIR")
        print(" 0. Salir")

        choice = input("\n[🎯] Elige una opción: ").strip()

        if choice == "0":
            print("[👋] Saliendo...")
            break
        
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(section_map):
                section_map[idx]()
            else:
                print("[❌] Opción no válida.")
        except ValueError:
            print("[❌] Entrada inválida.")

if __name__ == "__main__":
    main_menu()