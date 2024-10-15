# xss_check
<span style="color: red;">This text is red!</span>
This tool can check GET / POST / CSS / JS parameters and automatically scan parameters. Read the README.md file for more information on how to use the tool. Also, read the LICENSE file to know what you can and can't do with the tool.

***XSS Vulnerability Scanner***
This tool is designed to scan for Cross-Site Scripting (XSS) vulnerabilities in GET and POST parameters, as well as scan for potential vulnerabilities in CSS and JavaScript parameters. It supports using multiple wordlists to test a wide range of payloads.

__Features__ 
Automatically discover GET and POST parameters.
Scans for XSS vulnerabilities in GET and POST requests.
Scans for potential vulnerabilities in dynamic CSS and JavaScript parameters.
Accepts multiple wordlists for payload testing.
Requirements
To run the tool, you need to install the following Python packages:
```pip install argparse requests colorama beautifulsoup4```

__Usage__
Basic Usage
To scan a target URL for XSS vulnerabilities:
```python xss_scanner.py -u <target_url> -m <method> -w <wordlist_path>```

Arguments:

-u, --url: The target URL to scan.
-m, --method: The HTTP method to use (GET or POST). Default is GET.
-w, --wordlist: Path to the wordlist file containing payloads for testing GET and POST parameters.
Example:
```python xss_scanner.py -u "http://example.com/search?q=test" -m GET -w payloads.txt```

Scanning CSS and JavaScript Parameters
You can also supply additional wordlists for CSS and JavaScript scanning:
```python xss_scanner.py -u <target_url> -m <method> -w <post_wordlist> -wc <css_wordlist> -wj <js_wordlist>```

Arguments:

-wc, --wordlist2: Path to a wordlist for testing CSS parameters.
-wj, --wordlist3: Path to a wordlist for testing JavaScript parameters.

Example:
```python xss_scanner.py -u "http://example.com/search" -m POST -w post_payloads.txt -wc css_payloads.txt -wj js_payloads.txt```

