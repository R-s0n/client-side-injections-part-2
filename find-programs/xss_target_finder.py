#!/usr/bin/env python3

import os
import sys
import json
import argparse
import requests
import time
import random
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs
import logging
from typing import List, Dict, Optional, Set, Tuple
import re
import glob
import hashlib
from collections import defaultdict

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from webdriver_manager.chrome import ChromeDriverManager
    from wakepy import keep
except ImportError:
    print("Error: Required packages not installed. Please run: pip install -r requirements.txt")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

logging.getLogger('WDM').setLevel(logging.ERROR)
logging.getLogger('selenium').setLevel(logging.ERROR)
logging.getLogger('urllib3').setLevel(logging.ERROR)


class TargetFinder:
    def __init__(self, hackerone_key: Optional[str], bugcrowd_key: Optional[str], 
                 injection_type: str, use_subdomains: bool, verbose: bool = False):
        self.hackerone_key = hackerone_key
        self.bugcrowd_key = bugcrowd_key
        self.injection_type = injection_type
        self.use_subdomains = use_subdomains
        self.verbose = verbose
        self.driver = None
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
    def download_matching_chromedriver(self, chrome_version):
        import subprocess
        import zipfile
        from pathlib import Path
        
        driver_dir = Path.home() / '.chromedriver' / f'v{chrome_version}'
        driver_path = driver_dir / 'chromedriver'
        
        if driver_path.exists():
            logger.info(f"Using cached ChromeDriver for version {chrome_version}")
            return str(driver_path)
        
        driver_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Downloading ChromeDriver for Chrome/Chromium {chrome_version}...")
        
        try:
            response = requests.get(
                f'https://googlechromelabs.github.io/chrome-for-testing/LATEST_RELEASE_{chrome_version}',
                timeout=10
            )
            driver_version = response.text.strip()
            
            download_url = f'https://storage.googleapis.com/chrome-for-testing-public/{driver_version}/linux64/chromedriver-linux64.zip'
            
            zip_path = driver_dir / 'chromedriver.zip'
            response = requests.get(download_url, timeout=60)
            
            if response.status_code == 200:
                with open(zip_path, 'wb') as f:
                    f.write(response.content)
                
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(driver_dir)
                
                extracted_driver = driver_dir / 'chromedriver-linux64' / 'chromedriver'
                if extracted_driver.exists():
                    extracted_driver.rename(driver_path)
                    driver_path.chmod(0o755)
                    
                    import shutil
                    shutil.rmtree(driver_dir / 'chromedriver-linux64', ignore_errors=True)
                    zip_path.unlink(missing_ok=True)
                    
                    logger.info(f"✓ ChromeDriver {driver_version} installed successfully")
                    return str(driver_path)
        except Exception as e:
            logger.warning(f"Failed to download matching ChromeDriver: {e}")
            
        return None
    
    def init_browser(self):
        if self.driver:
            return
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--disable-blink-features=AutomationControlled')
        chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])
        chrome_options.add_argument('--log-level=3')
        
        try:
            import os
            import subprocess
            
            os.environ['WDM_LOG'] = '0'
            os.environ['WDM_LOG_LEVEL'] = '0'
            
            chrome_version = None
            try:
                chrome_version_output = subprocess.check_output(
                    ['chromium', '--version'], 
                    stderr=subprocess.DEVNULL
                ).decode('utf-8').strip()
                chrome_version = chrome_version_output.split()[1].split('.')[0]
                logger.info(f"Detected Chromium version: {chrome_version}")
            except:
                try:
                    chrome_version_output = subprocess.check_output(
                        ['google-chrome', '--version'],
                        stderr=subprocess.DEVNULL
                    ).decode('utf-8').strip()
                    chrome_version = chrome_version_output.split()[2].split('.')[0]
                    logger.info(f"Detected Chrome version: {chrome_version}")
                except:
                    logger.warning("Could not detect Chrome/Chromium version")
            
            driver_path = None
            if chrome_version and int(chrome_version) >= 115:
                driver_path = self.download_matching_chromedriver(chrome_version)
            
            if driver_path:
                self.driver = webdriver.Chrome(
                    service=Service(driver_path),
                    options=chrome_options
                )
            else:
                self.driver = webdriver.Chrome(
                    service=Service(ChromeDriverManager().install()),
                    options=chrome_options
                )
            
            self.driver.set_page_load_timeout(30)
            logger.info("✓ Browser initialized successfully - webpack detection enabled")
            
        except Exception as e:
            logger.warning(f"Failed to initialize browser: {str(e)[:100]}")
            logger.warning("Continuing without browser-based checks (webpack detection will be skipped)")
            self.driver = None
            
    def close_browser(self):
        if self.driver:
            self.driver.quit()
            self.driver = None
            
    def fetch_hackerone_programs(self) -> List[Dict]:
        if not self.hackerone_key:
            return []
            
        logger.info("Fetching HackerOne programs...")
        programs = []
        page = 1
        
        username, token = self.hackerone_key.split(':') if ':' in self.hackerone_key else (self.hackerone_key, '')
        
        while True:
            try:
                url = f"https://api.hackerone.com/v1/hackers/programs"
                params = {'page[number]': page, 'page[size]': 100}
                
                headers = {
                    'Accept': 'application/json',
                }
                
                response = self.session.get(
                    url,
                    auth=(username, token),
                    headers=headers,
                    params=params,
                    timeout=30
                )
                
                if response.status_code != 200:
                    logger.error(f"HackerOne API error: {response.status_code}")
                    if self.verbose:
                        logger.error(f"Response: {response.text[:500]}")
                    logger.error(f"Make sure your API key format is: identifier:token")
                    break
                    
                data = response.json()
                batch = data.get('data', [])
                
                if not batch:
                    break
                    
                for program in batch:
                    try:
                        handle = program['attributes']['handle']
                        scope_response = self.session.get(
                            f"https://api.hackerone.com/v1/hackers/programs/{handle}",
                            auth=(username, token),
                            headers=headers,
                            timeout=30
                        )
                        
                        if scope_response.status_code == 200:
                            scope_data = scope_response.json()
                            programs.append({
                                'platform': 'hackerone',
                                'name': program['attributes']['name'],
                                'handle': handle,
                                'url': f"https://hackerone.com/{handle}",
                                'data': scope_data
                            })
                            time.sleep(1)
                    except Exception as e:
                        logger.warning(f"Error fetching program details: {e}")
                        
                page += 1
                time.sleep(2)
                
                if len(batch) < 100:
                    break
                    
            except Exception as e:
                logger.error(f"Error fetching HackerOne programs: {e}")
                if self.verbose:
                    import traceback
                    logger.error(traceback.format_exc())
                time.sleep(5)
                break
                
        logger.info(f"Found {len(programs)} HackerOne programs")
        return programs
        
    def fetch_bugcrowd_programs(self) -> List[Dict]:
        if not self.bugcrowd_key:
            return []
            
        logger.info("Fetching BugCrowd programs...")
        programs = []
        
        try:
            headers = {
                'Authorization': f'Token {self.bugcrowd_key}',
                'Accept': 'application/vnd.bugcrowd.v4+json'
            }
            
            response = self.session.get(
                'https://api.bugcrowd.com/programs',
                headers=headers,
                timeout=30
            )
            
            if response.status_code != 200:
                logger.error(f"BugCrowd API error: {response.status_code}")
                return []
                
            data = response.json()
            
            for program in data.get('programs', []):
                if program.get('public', False):
                    try:
                        program_code = program.get('code')
                        target_response = self.session.get(
                            f'https://api.bugcrowd.com/programs/{program_code}/targets',
                            headers=headers,
                            timeout=30
                        )
                        
                        if target_response.status_code == 200:
                            programs.append({
                                'platform': 'bugcrowd',
                                'name': program.get('name'),
                                'code': program_code,
                                'url': f"https://bugcrowd.com/{program_code}",
                                'data': target_response.json()
                            })
                            time.sleep(1)
                    except Exception as e:
                        logger.warning(f"Error fetching program targets: {e}")
                        
        except Exception as e:
            logger.error(f"Error fetching BugCrowd programs: {e}")
            
        logger.info(f"Found {len(programs)} BugCrowd programs")
        return programs
        
    def extract_targets(self, program: Dict) -> List[str]:
        targets = []
        platform = program.get('platform', 'unknown')
        
        if platform == 'hackerone':
            try:
                relationships = program['data'].get('relationships', {})
                structured_scopes = relationships.get('structured_scopes', {}).get('data', [])
                
                for scope in structured_scopes:
                    attrs = scope.get('attributes', {})
                    if not attrs.get('eligible_for_submission', True):
                        continue
                        
                    asset_type = attrs.get('asset_type', '')
                    asset_identifier = attrs.get('asset_identifier', '')
                    
                    if asset_type in ['URL', 'WILDCARD']:
                        if asset_type == 'WILDCARD':
                            if self.use_subdomains:
                                targets.append(asset_identifier)
                            else:
                                clean_domain = asset_identifier.replace('*.', '')
                                if not clean_domain.startswith('http'):
                                    targets.append(f"https://{clean_domain}")
                                else:
                                    targets.append(clean_domain)
                        else:
                            if not asset_identifier.startswith(('http://', 'https://')):
                                asset_identifier = f"https://{asset_identifier}"
                            targets.append(asset_identifier)
            except Exception as e:
                logger.warning(f"Error extracting HackerOne targets: {e}")
                if self.verbose:
                    import traceback
                    logger.error(traceback.format_exc())
                
        elif platform == 'bugcrowd':
            try:
                for target in program['data'].get('targets', []):
                    target_name = target.get('name', '')
                    if 'http' in target_name.lower() or '.' in target_name:
                        if '*' in target_name and self.use_subdomains:
                            targets.append(target_name)
                        elif '*' not in target_name:
                            if not target_name.startswith('http'):
                                targets.append(f"https://{target_name}")
                            else:
                                targets.append(target_name)
                        elif '*' in target_name and not self.use_subdomains:
                            clean_domain = target_name.replace('*.', '')
                            targets.append(f"https://{clean_domain}")
            except Exception as e:
                logger.warning(f"Error extracting BugCrowd targets: {e}")
                if self.verbose:
                    import traceback
                    logger.error(traceback.format_exc())
                
        return targets
        
    def enumerate_subdomains(self, wildcard: str) -> List[str]:
        subdomains = []
        domain = wildcard.replace('*.', '')
        
        logger.info(f"Enumerating subdomains for {domain} via certificate transparency...")
        
        try:
            response = self.session.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=30
            )
            
            if response.status_code == 200:
                certs = response.json()
                found_domains = set()
                
                for cert in certs:
                    name_value = cert.get('name_value', '')
                    for subdomain in name_value.split('\n'):
                        subdomain = subdomain.strip()
                        if subdomain and '*' not in subdomain:
                            found_domains.add(subdomain)
                            
                for subdomain in list(found_domains)[:50]:
                    subdomains.append(f"https://{subdomain}")
                    
        except Exception as e:
            logger.warning(f"Error enumerating subdomains: {e}")
            
        if not subdomains:
            subdomains.append(f"https://{domain}")
            
        return subdomains
    
    def fetch_javascript_content(self, url: str, js_url: str) -> Optional[str]:
        try:
            full_url = urljoin(url, js_url)
            response = self.session.get(full_url, timeout=15, verify=True)
            if response.status_code == 200:
                return response.text
        except Exception as e:
            if self.verbose:
                logger.warning(f"Failed to fetch JS from {js_url}: {e}")
        return None
    
    def is_custom_javascript(self, js_content: str, js_url: str) -> Tuple[bool, str]:
        if not js_content:
            return False, "No content"
        
        indicators = {
            'npm_package': 0,
            'custom': 0
        }
        
        npm_patterns = [
            r'node_modules',
            r'/*!.*?https?://npmjs\.com',
            r'@license',
            r'webpack://',
            r'//# sourceMappingURL=.*node_modules',
            r'typeof exports.*typeof module',
            r'__webpack_require__',
            r'__esModule',
        ]
        
        for pattern in npm_patterns:
            if re.search(pattern, js_content[:5000], re.IGNORECASE):
                indicators['npm_package'] += 1
        
        custom_patterns = [
            r'function\s+[a-zA-Z_$][a-zA-Z0-9_$]*\s*\(',
            r'const\s+[a-zA-Z_$][a-zA-Z0-9_$]*\s*=',
            r'let\s+[a-zA-Z_$][a-zA-Z0-9_$]*\s*=',
            r'class\s+[a-zA-Z_$][a-zA-Z0-9_$]*',
        ]
        
        for pattern in custom_patterns:
            matches = re.findall(pattern, js_content[:10000])
            if len(matches) > 5:
                indicators['custom'] += 1
        
        parsed_url = urlparse(js_url)
        path = parsed_url.path.lower()
        
        if any(marker in path for marker in ['bundle', 'app', 'main', 'custom', 'script']):
            indicators['custom'] += 2
        
        if any(marker in path for marker in ['vendor', 'lib', 'framework', 'jquery', 'lodash', 'react', 'vue', 'angular']):
            indicators['npm_package'] += 2
        
        if indicators['custom'] > indicators['npm_package']:
            return True, f"custom:{indicators['custom']},npm:{indicators['npm_package']}"
        elif indicators['npm_package'] > indicators['custom']:
            return False, f"custom:{indicators['custom']},npm:{indicators['npm_package']}"
        else:
            return False, "unclear"
    
    def analyze_dom_xss_patterns(self, js_content: str, html_content: str = "") -> Dict:
        patterns = {
            'dangerous_sinks': [],
            'sources': [],
            'prototype_pollution': [],
            'dangerous_functions': [],
            'merge_operations': [],
            'postmessage_handlers': [],
            'storage_operations': [],
            'event_handlers': [],
            'dom_manipulation': [],
            'framework_unsafe': [],
        }
        
        sink_patterns = {
            'innerHTML': r'\.innerHTML\s*[=+]',
            'outerHTML': r'\.outerHTML\s*[=+]',
            'insertAdjacentHTML': r'\.insertAdjacentHTML\s*\(',
            'document.write': r'document\.write(ln)?\s*\(',
            'eval': r'\beval\s*\(',
            'Function_constructor': r'new\s+Function\s*\(',
            'setTimeout_string': r'setTimeout\s*\(\s*["\']',
            'setInterval_string': r'setInterval\s*\(\s*["\']',
            'script_injection': r'createElement\s*\(\s*["\']script["\']',
            'setAttribute_event': r'\.setAttribute\s*\(\s*["\']on\w+',
            'srcdoc': r'\.srcdoc\s*=',
            'location_assign': r'location\.(assign|replace|href)\s*[=\(]',
            'element_src': r'\.src\s*=.*?(location|hash|search|href)',
            'element_href': r'\.href\s*=.*?(location|hash|search|href)',
        }
        
        for sink_name, pattern in sink_patterns.items():
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            if matches:
                patterns['dangerous_sinks'].append({
                    'type': sink_name,
                    'count': len(matches)
                })
        
        source_patterns = {
            'location.hash': r'location\.hash',
            'location.search': r'location\.search',
            'location.href': r'location\.href',
            'document.referrer': r'document\.referrer',
            'window.name': r'window\.name',
            'postMessage': r'addEventListener\s*\(\s*["\']message["\']',
            'URLSearchParams': r'new\s+URLSearchParams',
        }
        
        for source_name, pattern in source_patterns.items():
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            if matches:
                patterns['sources'].append({
                    'type': source_name,
                    'count': len(matches)
                })
        
        proto_patterns = {
            'Object.assign': r'Object\.assign\s*\(',
            '__proto__': r'__proto__',
            'constructor': r'\[[\s\'"]*constructor[\s\'"]*\]',
            'prototype': r'\.prototype\s*[=\[]',
            'setPrototypeOf': r'Object\.setPrototypeOf',
            'Object.create': r'Object\.create',
        }
        
        for proto_name, pattern in proto_patterns.items():
            matches = re.findall(pattern, js_content)
            if matches:
                patterns['prototype_pollution'].append({
                    'type': proto_name,
                    'count': len(matches)
                })
        
        merge_patterns = {
            'lodash_merge': r'_\.merge\s*\(',
            'jQuery_extend': r'\$\.extend\s*\(',
            'deepmerge': r'deepmerge\s*\(',
            'Object.assign': r'Object\.assign\s*\(',
            'spread_operator': r'\{\.\.\..*?\}',
            'custom_merge': r'function\s+\w*merge\w*\s*\(',
        }
        
        for merge_name, pattern in merge_patterns.items():
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            if matches:
                patterns['merge_operations'].append({
                    'type': merge_name,
                    'count': len(matches)
                })
        
        postmessage_pattern = r'addEventListener\s*\(\s*["\']message["\'].*?\{[\s\S]{0,500}?\}'
        postmessage_handlers = re.findall(postmessage_pattern, js_content, re.DOTALL)
        for handler in postmessage_handlers:
            has_origin_check = bool(re.search(r'origin\s*[!=]=', handler))
            patterns['postmessage_handlers'].append({
                'has_origin_check': has_origin_check,
                'risky': not has_origin_check
            })
        
        storage_patterns = {
            'localStorage_read': r'localStorage\.getItem',
            'sessionStorage_read': r'sessionStorage\.getItem',
            'localStorage_write': r'localStorage\.setItem',
            'cookie_read': r'document\.cookie',
        }
        
        for storage_name, pattern in storage_patterns.items():
            matches = re.findall(pattern, js_content)
            if matches:
                patterns['storage_operations'].append({
                    'type': storage_name,
                    'count': len(matches)
                })
        
        event_patterns = {
            'dynamic_handler': r'\[[\'"]\s*on\w+\s*[\'"]\]\s*=',
            'setAttribute_on': r'\.setAttribute\s*\(\s*["\']on\w+',
            'addEventListener': r'\.addEventListener\s*\(',
        }
        
        for event_name, pattern in event_patterns.items():
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            if matches:
                patterns['event_handlers'].append({
                    'type': event_name,
                    'count': len(matches)
                })
        
        framework_unsafe_patterns = {
            'dangerouslySetInnerHTML': r'dangerouslySetInnerHTML',
            'v-html': r'v-html',
            'ng-bind-html': r'ng-bind-html',
            '$sce.trustAsHtml': r'\$sce\.trustAsHtml',
        }
        
        combined_content = js_content + "\n" + html_content
        for framework_name, pattern in framework_unsafe_patterns.items():
            matches = re.findall(pattern, combined_content, re.IGNORECASE)
            if matches:
                patterns['framework_unsafe'].append({
                    'type': framework_name,
                    'count': len(matches)
                })
        
        return patterns
    
    def analyze_security_headers(self, headers: Dict) -> Dict:
        security_analysis = {
            'csp': {
                'present': False,
                'strict': True,
                'unsafe_inline': False,
                'unsafe_eval': False,
                'directives': {},
                'score': 0
            },
            'sri': {
                'present': False,
                'scripts_with_sri': 0
            },
            'x_frame_options': {
                'present': False,
                'value': None,
                'secure': False
            },
            'content_type': {
                'present': False,
                'value': None,
                'nosniff': False
            },
            'overall_score': 0
        }
        
        csp_header = headers.get('Content-Security-Policy', '')
        if csp_header:
            security_analysis['csp']['present'] = True
            
            if "'unsafe-inline'" in csp_header:
                security_analysis['csp']['unsafe_inline'] = True
                security_analysis['csp']['strict'] = False
            
            if "'unsafe-eval'" in csp_header:
                security_analysis['csp']['unsafe_eval'] = True
                security_analysis['csp']['strict'] = False
            
            directives = {}
            for directive in csp_header.split(';'):
                directive = directive.strip()
                if directive:
                    parts = directive.split(None, 1)
                    if len(parts) >= 1:
                        directives[parts[0]] = parts[1] if len(parts) > 1 else ''
            
            security_analysis['csp']['directives'] = directives
            
            if security_analysis['csp']['strict']:
                security_analysis['csp']['score'] = 30
            elif security_analysis['csp']['unsafe_inline'] and not security_analysis['csp']['unsafe_eval']:
                security_analysis['csp']['score'] = 15
            else:
                security_analysis['csp']['score'] = 5
        else:
            security_analysis['csp']['score'] = -20
        
        x_frame = headers.get('X-Frame-Options', '')
        if x_frame:
            security_analysis['x_frame_options']['present'] = True
            security_analysis['x_frame_options']['value'] = x_frame
            if x_frame.lower() in ['deny', 'sameorigin']:
                security_analysis['x_frame_options']['secure'] = True
        
        content_type = headers.get('Content-Type', '')
        if content_type:
            security_analysis['content_type']['present'] = True
            security_analysis['content_type']['value'] = content_type
        
        x_content_type = headers.get('X-Content-Type-Options', '')
        if x_content_type and 'nosniff' in x_content_type.lower():
            security_analysis['content_type']['nosniff'] = True
        
        security_analysis['overall_score'] = security_analysis['csp']['score']
        
        return security_analysis
    
    def analyze_inline_scripts(self, html_content: str) -> Dict:
        inline_analysis = {
            'count': 0,
            'total_size': 0,
            'has_nonce': False,
            'patterns': {}
        }
        
        script_pattern = r'<script[^>]*>(.*?)</script>'
        inline_scripts = re.findall(script_pattern, html_content, re.DOTALL | re.IGNORECASE)
        
        inline_analysis['count'] = len(inline_scripts)
        
        nonce_pattern = r'<script[^>]*nonce=["\'][^"\']+["\']'
        if re.search(nonce_pattern, html_content, re.IGNORECASE):
            inline_analysis['has_nonce'] = True
        
        combined_scripts = '\n'.join(inline_scripts)
        inline_analysis['total_size'] = len(combined_scripts)
        
        if combined_scripts:
            inline_analysis['patterns'] = self.analyze_dom_xss_patterns(combined_scripts, html_content)
        
        return inline_analysis
    
    def check_source_maps(self, js_content: str, js_url: str) -> Dict:
        sourcemap_info = {
            'has_sourcemap': False,
            'exposes_node_modules': False,
            'sourcemap_url': None
        }
        
        sourcemap_pattern = r'//[#@]\s*sourceMappingURL=(.+)'
        match = re.search(sourcemap_pattern, js_content)
        
        if match:
            sourcemap_info['has_sourcemap'] = True
            sourcemap_info['sourcemap_url'] = match.group(1).strip()
            
            try:
                sourcemap_url = urljoin(js_url, sourcemap_info['sourcemap_url'])
                response = self.session.get(sourcemap_url, timeout=10)
                if response.status_code == 200:
                    sourcemap_content = response.text
                    if 'node_modules' in sourcemap_content:
                        sourcemap_info['exposes_node_modules'] = True
            except:
                pass
        
        return sourcemap_info
    
    def detect_vulnerable_libraries(self, js_content: str, html_content: str) -> List[Dict]:
        vulnerable_libs = []
        
        library_patterns = {
            'jquery': {
                'pattern': r'jQuery\s+v?(\d+\.\d+\.\d+)',
                'vulnerable_versions': ['1.', '2.', '3.0.', '3.1.', '3.2.', '3.3.', '3.4.0', '3.4.1']
            },
            'lodash': {
                'pattern': r'lodash.*?(\d+\.\d+\.\d+)',
                'vulnerable_versions': ['4.17.19', '4.17.18', '4.17.17', '4.17.16', '4.17.15']
            },
            'underscore': {
                'pattern': r'underscore.*?(\d+\.\d+\.\d+)',
                'vulnerable_versions': ['1.12.0', '1.11.0', '1.10.0', '1.9.', '1.8.']
            },
        }
        
        combined_content = js_content[:50000] + "\n" + html_content[:50000]
        
        for lib_name, lib_info in library_patterns.items():
            match = re.search(lib_info['pattern'], combined_content, re.IGNORECASE)
            if match:
                version = match.group(1)
                for vuln_version in lib_info['vulnerable_versions']:
                    if version.startswith(vuln_version):
                        vulnerable_libs.append({
                            'library': lib_name,
                            'version': version,
                            'issue': 'Known vulnerable version'
                        })
                        break
        
        return vulnerable_libs
        
    def detect_technology_stack(self, url: str) -> Dict:
        tech_info = {
            'frameworks': [],
            'has_csp': False,
            'csp_header': '',
            'has_auth': False,
            'has_waf': False,
            'custom_js': False,
            'js_files': [],
            'webpack_exposed': False,
            'response_headers': {},
            'status_code': None,
            'dom_analysis': {
                'custom_js_files': [],
                'npm_js_files': [],
                'inline_scripts': {},
                'combined_patterns': {},
                'security_headers': {},
                'vulnerable_libraries': [],
                'source_maps': [],
                'has_user_input_surfaces': False,
                'contenteditable_present': False,
            }
        }
        
        try:
            response = self.session.get(url, timeout=15, allow_redirects=True, verify=True)
            tech_info['status_code'] = response.status_code
            tech_info['response_headers'] = dict(response.headers)
            
            if response.status_code != 200:
                if self.verbose:
                    logger.info(f"Non-200 status code for {url}: {response.status_code}")
                return tech_info
            
            if 'Content-Security-Policy' in response.headers:
                tech_info['has_csp'] = True
                tech_info['csp_header'] = response.headers['Content-Security-Policy']
                
            waf_headers = ['X-WAF', 'X-CDN', 'Server', 'X-Powered-By', 'CF-RAY']
            for header in waf_headers:
                if header in response.headers:
                    value = response.headers[header].lower()
                    if any(waf in value for waf in ['cloudflare', 'akamai', 'imperva', 'f5', 'waf']):
                        tech_info['has_waf'] = True
                        break
                        
            html = response.text.lower()
            
            if any(keyword in html for keyword in ['login', 'signin', 'password', 'csrf', 'auth-token']):
                tech_info['has_auth'] = True
                
            framework_patterns = {
                'react': [r'react', r'_react', r'reactdom'],
                'vue': [r'vue\.js', r'__vue__', r'vue-'],
                'angular': [r'angular', r'ng-', r'_angular'],
                'svelte': [r'svelte'],
                'ember': [r'ember']
            }
            
            for framework, patterns in framework_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, html):
                        tech_info['frameworks'].append(framework)
                        break
                        
            script_tags = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', response.text, re.IGNORECASE)
            tech_info['js_files'] = script_tags[:20]
            
            if len(script_tags) > 3:
                tech_info['custom_js'] = True
            
            if self.injection_type == 'dom-based':
                tech_info['dom_analysis']['security_headers'] = self.analyze_security_headers(tech_info['response_headers'])
                
                tech_info['dom_analysis']['inline_scripts'] = self.analyze_inline_scripts(response.text)
                
                sri_pattern = r'<script[^>]+integrity=["\'][^"\']+["\']'
                sri_scripts = re.findall(sri_pattern, response.text, re.IGNORECASE)
                tech_info['dom_analysis']['security_headers']['sri']['scripts_with_sri'] = len(sri_scripts)
                if sri_scripts:
                    tech_info['dom_analysis']['security_headers']['sri']['present'] = True
                
                user_input_patterns = [
                    r'<(input|textarea)[^>]*>',
                    r'<form[^>]*>',
                    r'contenteditable\s*=\s*["\']true["\']',
                    r'comment',
                    r'wysiwyg',
                ]
                for pattern in user_input_patterns:
                    if re.search(pattern, response.text.lower()):
                        tech_info['dom_analysis']['has_user_input_surfaces'] = True
                        break
                
                if re.search(r'contenteditable', response.text, re.IGNORECASE):
                    tech_info['dom_analysis']['contenteditable_present'] = True
                
                all_js_content = []
                all_js_patterns = {
                    'dangerous_sinks': [],
                    'sources': [],
                    'prototype_pollution': [],
                    'merge_operations': [],
                    'postmessage_handlers': [],
                    'storage_operations': [],
                    'event_handlers': [],
                    'framework_unsafe': [],
                }
                
                js_files_to_analyze = script_tags[:10]
                
                for js_file in js_files_to_analyze:
                    try:
                        js_content = self.fetch_javascript_content(url, js_file)
                        if js_content:
                            is_custom, classification = self.is_custom_javascript(js_content, js_file)
                            
                            js_info = {
                                'url': js_file,
                                'is_custom': is_custom,
                                'classification': classification,
                                'size': len(js_content),
                                'patterns': {}
                            }
                            
                            if is_custom:
                                patterns = self.analyze_dom_xss_patterns(js_content, response.text)
                                js_info['patterns'] = patterns
                                
                                for key in all_js_patterns:
                                    if key in patterns and key not in ['dangerous_sinks', 'sources']:
                                        all_js_patterns[key].extend(patterns[key])
                                
                                sourcemap_info = self.check_source_maps(js_content, urljoin(url, js_file))
                                if sourcemap_info['has_sourcemap']:
                                    tech_info['dom_analysis']['source_maps'].append({
                                        'js_file': js_file,
                                        'exposes_node_modules': sourcemap_info['exposes_node_modules']
                                    })
                                
                                tech_info['dom_analysis']['custom_js_files'].append(js_info)
                                all_js_content.append(js_content[:50000])
                            else:
                                tech_info['dom_analysis']['npm_js_files'].append(js_info)
                                all_js_content.append(js_content[:10000])
                        
                        time.sleep(0.5)
                    except Exception as e:
                        if self.verbose:
                            logger.warning(f"Error analyzing JS file {js_file}: {e}")
                
                inline_scripts = tech_info['dom_analysis'].get('inline_scripts', {})
                if inline_scripts.get('patterns'):
                    inline_patterns = inline_scripts['patterns']
                    if 'dangerous_sinks' in inline_patterns:
                        all_js_patterns['dangerous_sinks'].extend(inline_patterns['dangerous_sinks'])
                    if 'sources' in inline_patterns:
                        all_js_patterns['sources'].extend(inline_patterns['sources'])
                
                tech_info['dom_analysis']['combined_patterns'] = all_js_patterns
                
                combined_js = '\n'.join(all_js_content)
                tech_info['dom_analysis']['vulnerable_libraries'] = self.detect_vulnerable_libraries(
                    combined_js, response.text
                )
                
        except requests.exceptions.ConnectionError as e:
            if self.verbose:
                logger.warning(f"Connection error for {url}: DNS resolution failed or host unreachable")
        except Exception as e:
            if self.verbose:
                logger.warning(f"Error in basic tech detection for {url}: {e}")
            
        try:
            self.init_browser()
            if self.driver:
                self.driver.get(url)
                time.sleep(3)
                
                scripts = self.driver.execute_script("""
                    var scripts = document.getElementsByTagName('script');
                    var info = {hasWebpack: false, jsCount: scripts.length};
                    for(var i = 0; i < scripts.length; i++) {
                        if(scripts[i].src && (scripts[i].src.includes('webpack') || scripts[i].src.includes('bundle'))) {
                            info.hasWebpack = true;
                        }
                    }
                    if(typeof webpackJsonp !== 'undefined' || typeof __webpack_require__ !== 'undefined') {
                        info.hasWebpack = true;
                    }
                    return info;
                """)
                
                if scripts.get('hasWebpack'):
                    webpack_check = self.driver.execute_script("""
                        if(typeof __webpack_require__ !== 'undefined' && __webpack_require__.m) {
                            return {exposed: true, moduleCount: Object.keys(__webpack_require__.m).length};
                        }
                        return {exposed: false};
                    """)
                    
                    if webpack_check.get('exposed'):
                        tech_info['webpack_exposed'] = True
                        
        except Exception as e:
            error_str = str(e)
            if 'ERR_NAME_NOT_RESOLVED' in error_str or 'ERR_CONNECTION_REFUSED' in error_str:
                if self.verbose:
                    logger.warning(f"Browser error for {url}: Domain not accessible")
            elif self.verbose:
                logger.warning(f"Error in browser-based detection for {url}: {error_str[:100]}")
            
        return tech_info
        
    def is_good_target(self, tech_info: Dict, url: str) -> tuple[bool, str]:
        if tech_info['status_code'] != 200:
            reason = f"Non-200 status code: {tech_info['status_code'] or 'No response'}"
            if self.verbose:
                logger.info(f"❌ {url} - {reason}")
            return False, reason
        
        if self.injection_type == 'reflected-stored':
            virtual_dom_frameworks = ['react', 'vue', 'angular', 'svelte']
            detected_frameworks = [fw for fw in virtual_dom_frameworks if fw in tech_info['frameworks']]
            
            if detected_frameworks:
                reason = f"Has virtual DOM framework(s): {', '.join(detected_frameworks)}"
                if self.verbose:
                    logger.info(f"❌ {url} - {reason}")
                return False, reason
            
            reason = "No virtual DOM frameworks detected - good for reflected/stored XSS"
            if self.verbose:
                logger.info(f"✓ {url} - {reason}")
            return True, reason
            
        elif self.injection_type == 'dom-based':
            dom_analysis = tech_info.get('dom_analysis', {})
            
            reasons = []
            score = 0
            
            custom_js_files = dom_analysis.get('custom_js_files', [])
            if len(custom_js_files) == 0:
                reason = "No custom JavaScript files detected"
                if self.verbose:
                    logger.info(f"❌ {url} - {reason}")
                return False, reason
            
            score += min(len(custom_js_files) * 2, 6)
            reasons.append(f"{len(custom_js_files)} custom JS file(s)")
            
            combined_patterns = dom_analysis.get('combined_patterns', {})
            
            dangerous_sinks = combined_patterns.get('dangerous_sinks', [])
            if dangerous_sinks:
                score += min(len(dangerous_sinks) * 3, 15)
                sink_types = list(set([s['type'] for s in dangerous_sinks[:3]]))
                reasons.append(f"Sinks: {', '.join(sink_types)}")
            
            sources = combined_patterns.get('sources', [])
            if sources:
                score += min(len(sources) * 2, 10)
                source_types = list(set([s['type'] for s in sources[:3]]))
                reasons.append(f"Sources: {', '.join(source_types)}")
            
            prototype_pollution = combined_patterns.get('prototype_pollution', [])
            if len(prototype_pollution) > 2:
                score += min(len(prototype_pollution) * 2, 12)
                proto_types = list(set([p['type'] for p in prototype_pollution[:2]]))
                reasons.append(f"Prototype: {', '.join(proto_types)}")
            
            merge_operations = combined_patterns.get('merge_operations', [])
            if len(merge_operations) > 1:
                score += min(len(merge_operations) * 3, 12)
                merge_types = list(set([m['type'] for m in merge_operations[:2]]))
                reasons.append(f"Merge ops: {', '.join(merge_types)}")
            
            postmessage_handlers = combined_patterns.get('postmessage_handlers', [])
            risky_postmessage = [h for h in postmessage_handlers if h.get('risky', False)]
            if risky_postmessage:
                score += min(len(risky_postmessage) * 8, 16)
                reasons.append(f"Risky postMessage ({len(risky_postmessage)})")
            
            storage_ops = combined_patterns.get('storage_operations', [])
            if len(storage_ops) > 0:
                score += min(len(storage_ops), 5)
            
            inline_scripts = dom_analysis.get('inline_scripts', {})
            if inline_scripts.get('count', 0) > 0:
                inline_patterns = inline_scripts.get('patterns', {})
                if inline_patterns.get('dangerous_sinks') or inline_patterns.get('sources'):
                    score += 8
                    reasons.append(f"Inline scripts ({inline_scripts['count']})")
            
            security_headers = dom_analysis.get('security_headers', {})
            csp = security_headers.get('csp', {})
            if not csp.get('present', False):
                score += 8
                reasons.append("No CSP")
            elif csp.get('unsafe_inline', False) or csp.get('unsafe_eval', False):
                score += 5
                reasons.append("Weak CSP")
            
            vulnerable_libs = dom_analysis.get('vulnerable_libraries', [])
            if vulnerable_libs:
                score += min(len(vulnerable_libs) * 12, 24)
                lib_names = [v['library'] for v in vulnerable_libs[:2]]
                reasons.append(f"Vuln libs: {', '.join(lib_names)}")
            
            source_maps = dom_analysis.get('source_maps', [])
            if any(sm.get('exposes_node_modules', False) for sm in source_maps):
                score += 5
                reasons.append("Source maps")
            
            if dom_analysis.get('has_user_input_surfaces', False):
                score += 5
                reasons.append("User input")
            
            if dom_analysis.get('contenteditable_present', False):
                score += 4
                reasons.append("ContentEditable")
            
            framework_unsafe = combined_patterns.get('framework_unsafe', [])
            if framework_unsafe:
                score += min(len(framework_unsafe) * 8, 16)
                unsafe_types = [f['type'] for f in framework_unsafe[:2]]
                reasons.append(f"Unsafe bindings: {', '.join(unsafe_types)}")
            
            if score >= 25:
                reason = " | ".join(reasons[:6])
                if self.verbose:
                    logger.info(f"✓ {url} - {reason}")
                return True, reason
            else:
                reason = f"Insufficient indicators (score: {score}/25 needed)"
                if self.verbose:
                    logger.info(f"❌ {url} - {reason}")
                return False, reason
                
        return False, "Does not meet criteria"
        
    def calculate_score(self, tech_info: Dict) -> int:
        score = 50
        
        if tech_info['has_csp']:
            csp = tech_info['csp_header'].lower()
            if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
                score -= 10
            else:
                score -= 30
                
        if tech_info['has_waf']:
            score -= 25
            
        if not tech_info['has_auth']:
            score += 20
        else:
            score -= 5
            
        if self.injection_type == 'reflected-stored':
            if not tech_info['frameworks']:
                score += 15
            if len(tech_info['js_files']) < 5:
                score += 10
                
        elif self.injection_type == 'dom-based':
            dom_analysis = tech_info.get('dom_analysis', {})
            
            custom_js_count = len(dom_analysis.get('custom_js_files', []))
            if custom_js_count > 0:
                score += min(custom_js_count * 2, 10)
            
            combined_patterns = dom_analysis.get('combined_patterns', {})
            
            sink_count = len(combined_patterns.get('dangerous_sinks', []))
            if sink_count > 0:
                score += min(sink_count * 2, 10)
            
            source_count = len(combined_patterns.get('sources', []))
            if source_count > 0:
                score += min(source_count * 2, 8)
            
            proto_count = len(combined_patterns.get('prototype_pollution', []))
            if proto_count > 2:
                score += min(proto_count, 10)
            
            merge_count = len(combined_patterns.get('merge_operations', []))
            if merge_count > 1:
                score += min(merge_count * 2, 10)
            
            postmessage_handlers = combined_patterns.get('postmessage_handlers', [])
            risky_postmessage = len([h for h in postmessage_handlers if h.get('risky', False)])
            if risky_postmessage > 0:
                score += min(risky_postmessage * 5, 15)
            
            vulnerable_libs = dom_analysis.get('vulnerable_libraries', [])
            if vulnerable_libs:
                score += min(len(vulnerable_libs) * 10, 20)
            
            security_headers = dom_analysis.get('security_headers', {})
            csp = security_headers.get('csp', {})
            if not csp.get('present', False):
                score += 5
            elif csp.get('unsafe_inline', False) or csp.get('unsafe_eval', False):
                score += 3
            
            inline_scripts = dom_analysis.get('inline_scripts', {})
            inline_patterns = inline_scripts.get('patterns', {})
            if inline_patterns.get('dangerous_sinks') or inline_patterns.get('sources'):
                score += 8
            
            if dom_analysis.get('has_user_input_surfaces', False):
                score += 3
            
            if dom_analysis.get('contenteditable_present', False):
                score += 3
            
            framework_unsafe_count = len(combined_patterns.get('framework_unsafe', []))
            if framework_unsafe_count > 0:
                score += min(framework_unsafe_count * 5, 10)
                
        x_frame = tech_info['response_headers'].get('X-Frame-Options', '').lower()
        if x_frame in ['deny', 'sameorigin']:
            score -= 5
            
        return max(0, min(100, score))
        
    def test_target(self, url: str, program: Optional[Dict] = None) -> Optional[Dict]:
        if url.startswith('https://https://') or url.startswith('http://http://'):
            if self.verbose:
                logger.warning(f"Skipping malformed URL: {url}")
            return None
        
        if self.verbose:
            logger.info(f"Testing target: {url}")
        
        try:
            tech_info = self.detect_technology_stack(url)
            
            if self.verbose:
                logger.info(f"  Status code: {tech_info['status_code']}")
                logger.info(f"  Frameworks detected: {tech_info['frameworks'] or 'None'}")
                logger.info(f"  Custom JS: {tech_info['custom_js']}")
                logger.info(f"  JS files: {len(tech_info['js_files'])}")
                logger.info(f"  CSP: {tech_info['has_csp']}")
                logger.info(f"  WAF: {tech_info['has_waf']}")
                logger.info(f"  Auth: {tech_info['has_auth']}")
                
                if self.injection_type == 'dom-based':
                    dom_analysis = tech_info.get('dom_analysis', {})
                    logger.info(f"  === DOM-Based Analysis ===")
                    logger.info(f"  Custom JS files: {len(dom_analysis.get('custom_js_files', []))}")
                    logger.info(f"  NPM JS files: {len(dom_analysis.get('npm_js_files', []))}")
                    
                    combined_patterns = dom_analysis.get('combined_patterns', {})
                    logger.info(f"  Dangerous sinks: {len(combined_patterns.get('dangerous_sinks', []))}")
                    logger.info(f"  Untrusted sources: {len(combined_patterns.get('sources', []))}")
                    logger.info(f"  Prototype pollution vectors: {len(combined_patterns.get('prototype_pollution', []))}")
                    logger.info(f"  Merge operations: {len(combined_patterns.get('merge_operations', []))}")
                    
                    postmessage = combined_patterns.get('postmessage_handlers', [])
                    risky_pm = len([h for h in postmessage if h.get('risky', False)])
                    logger.info(f"  Risky postMessage handlers: {risky_pm}")
                    
                    inline_scripts = dom_analysis.get('inline_scripts', {})
                    logger.info(f"  Inline scripts: {inline_scripts.get('count', 0)} (nonce: {inline_scripts.get('has_nonce', False)})")
                    
                    vulnerable_libs = dom_analysis.get('vulnerable_libraries', [])
                    if vulnerable_libs:
                        logger.info(f"  Vulnerable libraries: {[v['library'] for v in vulnerable_libs]}")
                    
                    security_headers = dom_analysis.get('security_headers', {})
                    csp = security_headers.get('csp', {})
                    logger.info(f"  CSP strict: {csp.get('strict', False)} (unsafe-inline: {csp.get('unsafe_inline', False)})")
                    
                    logger.info(f"  User input surfaces: {dom_analysis.get('has_user_input_surfaces', False)}")
                    logger.info(f"  ContentEditable: {dom_analysis.get('contenteditable_present', False)}")
            
            is_good, reason = self.is_good_target(tech_info, url)
            
            if not is_good:
                if not self.verbose:
                    logger.info(f"⊗ {url} - {reason}")
                return None
            
            score = self.calculate_score(tech_info)
            
            if self.verbose:
                logger.info(f"  Score: {score}/100")
            
            program_url = ''
            if program:
                if program['platform'] == 'hackerone':
                    program_url = f"https://hackerone.com/{program['handle']}"
                elif program['platform'] == 'bugcrowd':
                    program_url = f"https://bugcrowd.com/{program['code']}"
            
            return {
                'url': url,
                'score': score,
                'tech_info': tech_info,
                'reason': reason,
                'program_url': program_url
            }
            
        except Exception as e:
            logger.error(f"Error testing target {url}: {e}")
            if self.verbose:
                import traceback
                logger.error(traceback.format_exc())
            return None
            
    def load_existing_programs(self) -> Optional[tuple[List[Dict], str]]:
        program_files = sorted(glob.glob("programs_*.json"), reverse=True)
        
        if not program_files:
            return None
            
        latest_file = program_files[0]
        
        try:
            timestamp_str = latest_file.replace("programs_", "").replace(".json", "")
            file_datetime = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
            
            print(f"\nFound existing program data:")
            print(f"  File: {latest_file}")
            print(f"  Collected: {file_datetime.strftime('%Y-%m-%d %H:%M:%S')}")
            
            with open(latest_file, 'r') as f:
                programs = json.load(f)
            
            print(f"  Programs: {len(programs)}")
            
            while True:
                response = input("\nUse this data? (y/n): ").strip().lower()
                if response in ['y', 'yes']:
                    logger.info(f"Using existing program data from {latest_file}")
                    return programs, latest_file
                elif response in ['n', 'no']:
                    logger.info("Will fetch fresh program data")
                    return None
                else:
                    print("Please enter 'y' or 'n'")
                    
        except Exception as e:
            logger.warning(f"Error reading existing program file: {e}")
            return None
    
    def run(self, use_hackerone: bool, use_bugcrowd: bool):
        programs = []
        programs_file = None
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        existing_data = self.load_existing_programs()
        
        if existing_data:
            programs, programs_file = existing_data
        else:
            if use_hackerone and self.hackerone_key:
                programs.extend(self.fetch_hackerone_programs())
                
            if use_bugcrowd and self.bugcrowd_key:
                programs.extend(self.fetch_bugcrowd_programs())
                
            if not programs:
                logger.error("No programs found. Check API keys and connectivity.")
                return
                
            programs_file = f"programs_{timestamp}.json"
            
            with open(programs_file, 'w') as f:
                json.dump(programs, f, indent=2)
            logger.info(f"Saved {len(programs)} programs to {programs_file}")
        
        results_file = f"xss_targets_{self.injection_type}_{timestamp}.txt"
        
        logger.info("Starting continuous target testing...")
        logger.info(f"Injection type: {self.injection_type}")
        logger.info(f"Verbose mode: {self.verbose}")
        logger.info("Preventing system sleep mode...")
        tested_urls = set()
        targets_found = 0
        targets_tested = 0
        
        try:
            with keep.running():
                while True:
                    if not programs:
                        logger.info("All programs tested, reloading...")
                        
                        max_retries = 3
                        for retry in range(max_retries):
                            programs = []
                            try:
                                if use_hackerone and self.hackerone_key:
                                    programs.extend(self.fetch_hackerone_programs())
                                if use_bugcrowd and self.bugcrowd_key:
                                    programs.extend(self.fetch_bugcrowd_programs())
                                
                                if programs:
                                    break
                                else:
                                    logger.warning(f"No programs fetched, retry {retry + 1}/{max_retries}")
                                    time.sleep(10 * (retry + 1))
                            except Exception as e:
                                logger.error(f"Error fetching programs (retry {retry + 1}/{max_retries}): {e}")
                                time.sleep(10 * (retry + 1))
                        
                        if not programs:
                            logger.error("Failed to fetch programs after retries. Waiting 60s before trying again...")
                            time.sleep(60)
                            continue
                        
                        tested_urls.clear()
                        logger.info(f"Reloaded {len(programs)} programs. Stats: {targets_found} targets found from {targets_tested} tested")
                        
                    program = random.choice(programs)
                    programs.remove(program)
                    
                    logger.info(f"Testing program: {program['name']}")
                    
                    try:
                        targets = self.extract_targets(program)
                        
                        if self.verbose:
                            logger.info(f"  Extracted {len(targets)} target(s) from {program['name']}")
                            for t in targets[:5]:
                                logger.info(f"    - {t}")
                            if len(targets) > 5:
                                logger.info(f"    ... and {len(targets) - 5} more")
                        
                        if not targets:
                            if self.verbose:
                                logger.info(f"  No targets found for {program['name']}, skipping")
                            continue
                        
                        program_targets_tested = 0
                        program_targets_found = 0
                        
                        for target in targets:
                            try:
                                urls_to_test = []
                                
                                if '*' in target and self.use_subdomains:
                                    if self.verbose:
                                        logger.info(f"  Enumerating subdomains for wildcard: {target}")
                                    urls_to_test = self.enumerate_subdomains(target)
                                else:
                                    urls_to_test = [target]
                                    
                                for url in urls_to_test:
                                    if url in tested_urls:
                                        if self.verbose:
                                            logger.info(f"  Skipping already tested: {url}")
                                        continue
                                        
                                    tested_urls.add(url)
                                    targets_tested += 1
                                    program_targets_tested += 1
                                    
                                    try:
                                        result = self.test_target(url, program)
                                        
                                        if result:
                                            targets_found += 1
                                            program_targets_found += 1
                                            with open(results_file, 'a') as f:
                                                f.write(f"{result['url']} -- {result['score']} -- {result['program_url']}\n")
                                            logger.info(f"✓ TARGET FOUND ({targets_found}): {result['url']} -- {result['score']} -- {result['program_url']}")
                                            if self.verbose:
                                                logger.info(f"  Reason: {result['reason']}")
                                            
                                    except Exception as e:
                                        logger.warning(f"Error testing {url}: {e}")
                                        if self.verbose:
                                            import traceback
                                            logger.error(traceback.format_exc())
                                        continue
                                        
                                    time.sleep(random.uniform(2, 5))
                                    
                            except Exception as e:
                                logger.warning(f"Error processing target {target}: {e}")
                                continue
                                
                    except Exception as e:
                        logger.warning(f"Error extracting targets from {program['name']}: {e}")
                    
                    if self.verbose and 'program_targets_tested' in locals():
                        logger.info(f"  Program summary: Tested {program_targets_tested} URL(s), found {program_targets_found} good target(s)")
                        
                    time.sleep(5)
                    
        except KeyboardInterrupt:
            logger.info("\nStopping target finder...")
            logger.info("System sleep mode will be re-enabled")
        finally:
            self.close_browser()


def main():
    parser = argparse.ArgumentParser(
        description='Find good targets for client-side injection testing on bug bounty platforms'
    )
    
    parser.add_argument(
        '--hackerone', '-H',
        action='store_true',
        help='Use only HackerOne'
    )
    
    parser.add_argument(
        '--bugcrowd', '-B',
        action='store_true',
        help='Use only BugCrowd'
    )
    
    injection_group = parser.add_mutually_exclusive_group(required=True)
    injection_group.add_argument(
        '--reflected-stored',
        action='store_true',
        help='Optimize for reflected and stored XSS (avoid virtual DOM frameworks)'
    )
    
    injection_group.add_argument(
        '--dom-based',
        action='store_true',
        help='Optimize for DOM-based XSS and prototype pollution'
    )
    
    parser.add_argument(
        '--subdomains',
        action='store_true',
        help='Enumerate subdomains from certificate transparency logs for wildcards'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output showing detailed analysis of each target'
    )
    
    args = parser.parse_args()
    
    hackerone_key = os.getenv('HACKERONE_API_KEY')
    bugcrowd_key = os.getenv('BUGCROWD_API_KEY')
    
    if not hackerone_key and not bugcrowd_key:
        print("ERROR: No API keys found!")
        print("Please set at least one of the following environment variables:")
        print("  - HACKERONE_API_KEY (format: username:token)")
        print("  - BUGCROWD_API_KEY")
        sys.exit(1)
        
    use_hackerone = True
    use_bugcrowd = True
    
    if args.hackerone and not args.bugcrowd:
        use_bugcrowd = False
        if not hackerone_key:
            print("ERROR: --hackerone flag provided but HACKERONE_API_KEY not set")
            sys.exit(1)
    elif args.bugcrowd and not args.hackerone:
        use_hackerone = False
        if not bugcrowd_key:
            print("ERROR: --bugcrowd flag provided but BUGCROWD_API_KEY not set")
            sys.exit(1)
    else:
        if not hackerone_key:
            use_hackerone = False
            logger.warning("HACKERONE_API_KEY not set, skipping HackerOne")
        if not bugcrowd_key:
            use_bugcrowd = False
            logger.warning("BUGCROWD_API_KEY not set, skipping BugCrowd")
            
    injection_type = 'reflected-stored' if args.reflected_stored else 'dom-based'
    
    finder = TargetFinder(
        hackerone_key=hackerone_key,
        bugcrowd_key=bugcrowd_key,
        injection_type=injection_type,
        use_subdomains=args.subdomains,
        verbose=args.verbose
    )
    
    finder.run(use_hackerone=use_hackerone, use_bugcrowd=use_bugcrowd)


if __name__ == '__main__':
    main()


