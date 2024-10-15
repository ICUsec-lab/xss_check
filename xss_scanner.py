import argparse
import requests
from urllib.parse import urlparse, parse_qs
from colorama import Fore, Style
from bs4 import BeautifulSoup
import re

# Constants for colors
BLUE = Fore.BLUE
GREEN = Fore.GREEN
RED = Fore.RED
RESET = Style.RESET_ALL

def print_banner():
    """Prints the banner for the XSS scanner."""
    banner = f"""
    {BLUE}***************************************
    *       ICU v1.0 XSS Scanner         *
    ***************************************
    {RESET}
    """
    print(banner)

def read_wordlist(file_path):
    """Reads a wordlist file and returns a list of payloads."""
    try:
        with open(file_path, 'r') as file:
            return [line.strip() for line in file.readlines()]
    except FileNotFoundError:
        print(f"{RED}[-] Wordlist file not found: {file_path}{RESET}")
        return []

def auto_discover_params(method, url):
    """Auto discovers GET or POST parameters based on the method."""
    params = []
    with requests.Session() as session:
        try:
            response = session.get(url) if method == "GET" else session.post(url)
            response.raise_for_status()  # Raise an error for bad responses
            if method == "POST":
                soup = BeautifulSoup(response.text, 'html.parser')
                for input_tag in soup.find_all('input'):
                    param_name = input_tag.get('name')
                    if param_name and param_name not in params:
                        params.append(param_name)
            else:
                parsed_url = urlparse(url)
                query_params = parse_qs(parsed_url.query)
                params = list(query_params.keys())
        except requests.exceptions.RequestException as e:
            print(f"{RED}[-] Error discovering parameters: {e}{RESET}")
    return params

def check_xss_param(session, url, method, param, payload):
    """Checks for XSS vulnerabilities in the given parameter."""
    if method == "GET":
        full_url = f"{url}&{param}={payload}" if '?' in url else f"{url}?{param}={payload}"
        try:
            response = session.get(full_url)
            return param, payload, response.text
        except requests.exceptions.RequestException as e:
            print(f"{RED}[-] Request failed: {e}{RESET}")
            return param, payload, None
    else:
        data = {param: payload}
        try:
            response = session.post(url, data=data)
            return param, payload, response.text
        except requests.exceptions.RequestException as e:
            print(f"{RED}[-] Request failed: {e}{RESET}")
            return param, payload, None

def find_dynamic_css_js_params(response_text):
    """Extracts CSS and JS parameters from the response text."""
    soup = BeautifulSoup(response_text, 'html.parser')
    css_params = set()
    js_params = set()

    for link in soup.find_all('link', href=True):
        css_params.add(link['href'])

    for script in soup.find_all('script', src=True):
        js_params.add(script['src'])

    for tag in soup.find_all(True):
        for attr in tag.attrs:
            if 'on' in attr:
                js_params.add(f"{attr}={tag[attr]}")
            if isinstance(tag[attr], str) and ('=' in tag[attr]):
                js_params.add(tag[attr])

    return css_params, js_params

def is_valid_js_param(param):
    """Checks if the parameter value is not a URL."""
    url_pattern = re.compile(r'^(http|https|ftp):\/\/')
    return not url_pattern.match(param)

def check_xss(url, method, payload_wordlists, css_wordlist, js_wordlist, custom_get_params, custom_post_params, custom_css_params, custom_js_params, scan_post):
    """Main function to check for XSS vulnerabilities."""
    found_vulnerabilities = False

    payloads = []
    for wordlist in payload_wordlists:
        payloads.extend(read_wordlist(wordlist))

    css_payloads = read_wordlist(css_wordlist) if css_wordlist else []
    js_payloads = read_wordlist(js_wordlist) if js_wordlist else []

    parsed_url = urlparse(url)
    url_params = parse_qs(parsed_url.query)
    url_params_list = list(url_params.keys())

    params = auto_discover_params(method, url)

    print(f"{BLUE}Starting scan on URL: {url}{RESET}")

    if method == "GET" or custom_get_params:
        params += custom_get_params
        print(f"{BLUE}Found GET parameters: {', '.join(url_params_list + custom_get_params)}{RESET}")
        with requests.Session() as session:
            for param in url_params_list + custom_get_params:
                print(f"{BLUE}Scanning URL parameter: {param}{RESET}")
                vulnerabilities_found = False

                for payload in payloads:
                    param_name, test_payload, response_text = check_xss_param(session, url, "GET", param, payload)
                    if test_payload in response_text:
                        print(f"{GREEN}[+] XSS Vulnerability found for URL parameter: {param_name} with payload: {test_payload}{RESET}")
                        vulnerabilities_found = True

                if not vulnerabilities_found:
                    print(f"{RED}[-] No XSS vulnerabilities found for URL parameter: {param}{RESET}")

    if scan_post or custom_post_params:
        params += custom_post_params
        print(f"{BLUE}Found POST parameters: {', '.join(params)}{RESET}")
        with requests.Session() as session:
            for param in params:
                print(f"{BLUE}Scanning POST parameter: {param}{RESET}")
                vulnerabilities_found = False

                for payload in payloads:
                    param_name, test_payload, response_text = check_xss_param(session, url, method, param, payload)
                    if test_payload in response_text:
                        print(f"{GREEN}[+] XSS Vulnerability found for POST parameter: {param_name} with payload: {test_payload}{RESET}")
                        vulnerabilities_found = True

                if not vulnerabilities_found:
                    print(f"{RED}[-] No XSS vulnerabilities found for POST parameter: {param}{RESET}")

    print(f"{BLUE}Starting CSS scanning...{RESET}")
    custom_css_params_set = set(custom_css_params)  # Convert to set for easier handling
    with requests.Session() as session:
        response = session.get(url)
        css_params, js_params = find_dynamic_css_js_params(response.text)

        css_params.update(custom_css_params_set)  # Add custom CSS parameters to be scanned

        for param in css_params:
            print(f"{BLUE}Scanning CSS parameter: {param}{RESET}")
            vulnerabilities_found = False  # Initialize for each parameter

            for payload in css_payloads:
                full_url = f"{url}?{param}={payload}"
                response = session.get(full_url)
                if payload in response.text:
                    print(f"{GREEN}[+] XSS Vulnerability found for CSS parameter: {param} with payload: {payload}{RESET}")
                    vulnerabilities_found = True

            if not vulnerabilities_found:
                print(f"{RED}[-] No CSS vulnerabilities found for parameter: {param}{RESET}")

    print(f"{BLUE}Starting JS scanning...{RESET}")
    custom_js_params_set = set(custom_js_params)  # Convert to set for easier handling
    js_params.update(custom_js_params_set)  # Add custom JS parameters to be scanned

    for param in js_params:
        if is_valid_js_param(param):
            print(f"{BLUE}Scanning JS parameter: {param}{RESET}")
            vulnerabilities_found = False  # Initialize for each parameter

            for payload in js_payloads:
                full_url = f"{url}?{param}={payload}"
                with requests.Session() as session:
                    response = session.get(full_url)
                    if payload in response.text:
                        print(f"{GREEN}[+] XSS Vulnerability found for JS parameter: {param} with payload: {payload}{RESET}")
                        vulnerabilities_found = True

            if not vulnerabilities_found:
                print(f"{RED}[-] No JS vulnerabilities found for parameter: {param}{RESET}")

    if not found_vulnerabilities:
        print(f"{RED}[-] No XSS vulnerabilities found in any parameters.{RESET}")

def main():
    print_banner()  # Print the banner
    parser = argparse.ArgumentParser(description='XSS Vulnerability Scanner')
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-m', '--method', choices=['GET', 'POST'], default='GET', help='HTTP method to use')
    parser.add_argument('-w', '--wordlist', help='Path to the POST parameter payload wordlist')
    parser.add_argument('-wc', '--wordlist2', help='Path to an additional CSS parameter payload wordlist')
    parser.add_argument('-wj', '--wordlist3', help='Path to another JS parameter payload wordlist')
    parser.add_argument('-pg', '--get-params', nargs='+', help='Custom GET parameters to scan')
    parser.add_argument('-pp', '--post-params', nargs='+', help='Custom POST parameters to scan')
    parser.add_argument('-pc', '--css-params', nargs='+', help='Custom CSS parameters to scan')
    parser.add_argument('-pj', '--js-params', nargs='+', help='Custom JS parameters to scan')

    args = parser.parse_args()

    wordlists = []
    if args.wordlist:
        wordlists.append(args.wordlist)

    scan_post = bool(args.wordlist)

    custom_get_params = args.get_params if args.get_params else []
    custom_post_params = args.post_params if args.post_params else []
    custom_css_params = args.css_params if args.css_params else []
    custom_js_params = args.js_params if args.js_params else []

    check_xss(
        args.url,
        args.method,
        wordlists,
        args.wordlist2,
        args.wordlist3,
        custom_get_params,
        custom_post_params,
        custom_css_params,
        custom_js_params,
        scan_post
    )

if __name__ == "__main__":
    main()
