# xss_check
This tool can check GET / POST / CSS / JS parameters and automatically scan parameters. Read the README.md file for more information on how to use the tool. Also, read the LICENSE file to know what you can and can't do with the tool. This tool is designed to scan for Cross-Site Scripting (XSS) vulnerabilities in GET and POST parameters, as well as scan for potential vulnerabilities in CSS and JavaScript parameters. It supports using multiple wordlists to test a wide range of payloads. Features include automatically discovering GET and POST parameters, scanning for XSS vulnerabilities in GET and POST requests, scanning for potential vulnerabilities in dynamic CSS and JavaScript parameters, and accepting multiple wordlists for payload testing. To run the tool, you need to install the following Python packages: pip install argparse requests colorama beautifulsoup4. For basic usage, scan a target URL for XSS vulnerabilities by running the command python xss_scanner.py -u <target_url> -m <method> -w <wordlist_path>. The arguments are as follows: -u, --url: The target URL to scan; -m, --method: The HTTP method to use (GET or POST). Default is GET; -w, --wordlist: Path to the wordlist file containing payloads for testing GET and POST parameters. Example: python xss_scanner.py -u "http://example.com/search?q=test" -m GET -w payloads.txt. You can also supply additional wordlists for CSS and JavaScript scanning by running python xss_scanner.py -u <target_url> -m <method> -w <post_wordlist> -wc <css_wordlist> -wj <js_wordlist>. Here, -wc, --wordlist2 is the path to a wordlist for testing CSS parameters, and -wj, --wordlist3 is the path to a wordlist for testing JavaScript parameters. Example: python xss_scanner.py -u "http://example.com/search" -m POST -w post_payloads.txt -wc css_payloads.txt -wj js_payloads.txt.
