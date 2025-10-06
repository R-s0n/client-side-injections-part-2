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

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from webdriver_manager.chrome import ChromeDriverManager
except ImportError:
    print("Error: Required packages not installed. Please run: pip install -r requirements.txt")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class TargetFinder:
    def __init__(self, hackerone_key: Optional[str], bugcrowd_key: Optional[str], 
                 injection_type: str, use_subdomains: bool):
        self.hackerone_key = hackerone_key
        self.bugcrowd_key = bugcrowd_key
        self.injection_type = injection_type
        self.use_subdomains = use_subdomains
        self.driver = None
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
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
        
        try:
            self.driver = webdriver.Chrome(
                service=Service(ChromeDriverManager().install()),
                options=chrome_options
            )
            self.driver.set_page_load_timeout(30)
        except Exception as e:
            logger.error(f"Failed to initialize browser: {e}")
            
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
        
        if program['platform'] == 'hackerone':
            try:
                relationships = program['data'].get('data', {}).get('relationships', {})
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
                                targets.append(f"https://{clean_domain}")
                        else:
                            targets.append(asset_identifier)
            except Exception as e:
                logger.warning(f"Error extracting HackerOne targets: {e}")
                
        elif program['platform'] == 'bugcrowd':
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
            'response_headers': {}
        }
        
        try:
            response = self.session.get(url, timeout=15, allow_redirects=True)
            tech_info['response_headers'] = dict(response.headers)
            
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
                
        except Exception as e:
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
            logger.warning(f"Error in browser-based detection for {url}: {e}")
            
        return tech_info
        
    def is_good_target(self, tech_info: Dict) -> bool:
        if self.injection_type == 'reflected-stored':
            virtual_dom_frameworks = ['react', 'vue', 'angular', 'svelte']
            if any(fw in tech_info['frameworks'] for fw in virtual_dom_frameworks):
                return False
            return True
            
        elif self.injection_type == 'dom-based':
            if not tech_info['custom_js']:
                return False
                
            virtual_dom_frameworks = ['react', 'vue', 'angular']
            has_framework = any(fw in tech_info['frameworks'] for fw in virtual_dom_frameworks)
            
            if has_framework and tech_info['webpack_exposed']:
                return True
            elif has_framework and not tech_info['webpack_exposed']:
                return False
            elif not has_framework and tech_info['custom_js']:
                return True
                
        return False
        
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
        
    def test_target(self, url: str) -> Optional[Dict]:
        logger.info(f"Testing target: {url}")
        
        try:
            tech_info = self.detect_technology_stack(url)
            
            if not self.is_good_target(tech_info):
                logger.info(f"Target {url} does not match criteria for {self.injection_type}")
                return None
                
            score = self.calculate_score(tech_info)
            
            return {
                'url': url,
                'score': score,
                'tech_info': tech_info
            }
            
        except Exception as e:
            logger.error(f"Error testing target {url}: {e}")
            return None
            
    def run(self, use_hackerone: bool, use_bugcrowd: bool):
        programs = []
        
        if use_hackerone and self.hackerone_key:
            programs.extend(self.fetch_hackerone_programs())
            
        if use_bugcrowd and self.bugcrowd_key:
            programs.extend(self.fetch_bugcrowd_programs())
            
        if not programs:
            logger.error("No programs found. Check API keys and connectivity.")
            return
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        programs_file = f"programs_{timestamp}.json"
        
        with open(programs_file, 'w') as f:
            json.dump(programs, f, indent=2)
        logger.info(f"Saved {len(programs)} programs to {programs_file}")
        
        results_file = f"xss_targets_{self.injection_type}_{timestamp}.txt"
        
        logger.info("Starting continuous target testing...")
        tested_urls = set()
        
        try:
            while True:
                if not programs:
                    logger.info("All programs tested, reloading...")
                    programs = []
                    if use_hackerone and self.hackerone_key:
                        programs.extend(self.fetch_hackerone_programs())
                    if use_bugcrowd and self.bugcrowd_key:
                        programs.extend(self.fetch_bugcrowd_programs())
                    tested_urls.clear()
                    
                program = random.choice(programs)
                programs.remove(program)
                
                logger.info(f"Testing program: {program['name']}")
                targets = self.extract_targets(program)
                
                for target in targets:
                    urls_to_test = []
                    
                    if '*' in target and self.use_subdomains:
                        urls_to_test = self.enumerate_subdomains(target)
                    else:
                        urls_to_test = [target]
                        
                    for url in urls_to_test:
                        if url in tested_urls:
                            continue
                            
                        tested_urls.add(url)
                        result = self.test_target(url)
                        
                        if result:
                            with open(results_file, 'a') as f:
                                f.write(f"{result['url']} -- {result['score']}\n")
                            logger.info(f"✓ Added target: {result['url']} -- {result['score']}")
                            
                        time.sleep(random.uniform(2, 5))
                        
                time.sleep(5)
                
        except KeyboardInterrupt:
            logger.info("\nStopping target finder...")
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
        use_subdomains=args.subdomains
    )
    
    finder.run(use_hackerone=use_hackerone, use_bugcrowd=use_bugcrowd)


if __name__ == '__main__':
    main()

