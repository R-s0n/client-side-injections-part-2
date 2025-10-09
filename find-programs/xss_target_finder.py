#!/usr/bin/env python3

import os
import sys
import json
import argparse
import requests
import time
import random
from datetime import datetime
from urllib.parse import urlparse, urljoin
import logging
from typing import List, Dict, Optional, Set
import re
import glob

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
            'status_code': None
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
            if not tech_info['custom_js']:
                reason = "Insufficient custom JavaScript"
                if self.verbose:
                    logger.info(f"❌ {url} - {reason}")
                return False, reason
                
            virtual_dom_frameworks = ['react', 'vue', 'angular']
            has_framework = any(fw in tech_info['frameworks'] for fw in virtual_dom_frameworks)
            
            if has_framework and tech_info['webpack_exposed']:
                reason = "Framework with exposed webpack - good for DOM-based XSS"
                if self.verbose:
                    logger.info(f"✓ {url} - {reason}")
                return True, reason
            elif has_framework and not tech_info['webpack_exposed']:
                reason = "Framework detected but webpack not exposed"
                if self.verbose:
                    logger.info(f"❌ {url} - {reason}")
                return False, reason
            elif not has_framework and tech_info['custom_js']:
                reason = "Custom JavaScript without framework - good for DOM-based XSS"
                if self.verbose:
                    logger.info(f"✓ {url} - {reason}")
                return True, reason
                
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
            if tech_info['custom_js']:
                score += 15
            if tech_info['webpack_exposed']:
                score += 20
            if len(tech_info['js_files']) > 10:
                score += 10
                
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

