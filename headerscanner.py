from requests import get
from termcolor import colored
from os import get_terminal_size

def print_banner():
        banner = '''
░  ░░░░  ░░        ░░░      ░░░       ░░░        ░░       ░░░░      ░░░░      ░░░░      ░░░   ░░░  ░░   ░░░  ░░        ░░       ░░
▒  ▒▒▒▒  ▒▒  ▒▒▒▒▒▒▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒▒▒▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒▒▒▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒    ▒▒  ▒▒    ▒▒  ▒▒  ▒▒▒▒▒▒▒▒  ▒▒▒▒  ▒
▓        ▓▓      ▓▓▓▓  ▓▓▓▓  ▓▓  ▓▓▓▓  ▓▓      ▓▓▓▓       ▓▓▓▓      ▓▓▓  ▓▓▓▓▓▓▓▓  ▓▓▓▓  ▓▓  ▓  ▓  ▓▓  ▓  ▓  ▓▓      ▓▓▓▓       ▓▓
█  ████  ██  ████████        ██  ████  ██  ████████  ███  █████████  ██  ████  ██        ██  ██    ██  ██    ██  ████████  ███  ██
█  ████  ██        ██  ████  ██       ███        ██  ████  ███      ████      ███  ████  ██  ███   ██  ███   ██        ██  ████  █
        '''
        terminal_width = get_terminal_size().columns
        centered_banner = '\n'.join([line.center(terminal_width) for line in banner.split('\n')])
        print('\n' + colored(centered_banner, 'magenta') + '\n' + colored('by azuk4r', 'magenta').center(terminal_width))

def scan_headers(url):
        try:
                res = get(url, timeout=10)
                headers = res.headers
                results = []
                results.append(colored(f'Results for {url}:', 'cyan'))
                if 'Strict-Transport-Security' in headers:
                        results.append(colored('[+]', 'red') + f' Strict-Transport-Security: ' + colored('Present', 'red') + ' (HTTPS enforced)')
                else:
                        results.append(colored('[-]', 'green') + f' Strict-Transport-Security: ' + colored('Not present', 'green') + ' (HTTPS not enforced)')
                if 'Content-Security-Policy' in headers:
                        results.append(colored('[+]', 'red') + f' Content-Security-Policy: ' + colored('Present', 'red') + ' (CSP active)')
                else:
                        results.append(colored('[-]', 'green') + f' Content-Security-Policy: ' + colored('Not present', 'green') + ' (CSP missing)')
                cookies = headers.get('Set-Cookie', '')
                if 'Secure' in cookies and 'HttpOnly' in cookies:
                        results.append(colored('[+]', 'red') + f' Set-Cookie: ' + colored('Present', 'red') + ' (Cookies secure)')
                else:
                        results.append(colored('[-]', 'green') + f' Set-Cookie: ' + colored('Not present', 'green') + ' (Cookies vulnerable)')
                if 'X-Frame-Options' in headers:
                        results.append(colored('[+]', 'red') + f' X-Frame-Options: ' + colored('Present', 'red') + ' (Clickjacking protected)')
                else:
                        results.append(colored('[-]', 'green') + f' X-Frame-Options: ' + colored('Not present', 'green') + ' (Clickjacking risk)')
                if 'X-Content-Type-Options' in headers:
                        results.append(colored('[+]', 'red') + f' X-Content-Type-Options: ' + colored('Present', 'red') + ' (MIME sniffing disabled)')
                else:
                        results.append(colored('[-]', 'green') + f' X-Content-Type-Options: ' + colored('Not present', 'green') + ' (MIME sniffing possible)')
                if 'X-XSS-Protection' in headers:
                        results.append(colored('[+]', 'red') + f' X-XSS-Protection: ' + colored('Present', 'red') + ' (XSS protection enabled)')
                else:
                        results.append(colored('[-]', 'green') + f' X-XSS-Protection: ' + colored('Not present', 'green') + ' (XSS risk)')
                if 'Referrer-Policy' in headers:
                        results.append(colored('[+]', 'red') + f' Referrer-Policy: ' + colored('Present', 'red') + ' (Referrer policy active)')
                else:
                        results.append(colored('[-]', 'green') + f' Referrer-Policy: ' + colored('Not present', 'green') + ' (Referrer data exposed)')
                print('\n'.join(results) + '\n')
        except Exception as e:
                print(f'Error: {url}: {e}')

def scan_urls(urls):
        for url in urls:
                scan_headers(url)

urls = [
        'https://example.com'
]

print_banner()
scan_urls(urls)
