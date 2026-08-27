# scanners/parameter_discovery.py
import requests
from bs4 import BeautifulSoup
from typing import Dict, List

def discover_parameters(host: str) -> Dict[str, List[str]]:
    """Crawl the site and extract query parameters and form fields."""
    params = {"query": [], "form": []}
    try:
        resp = requests.get(f"https://{host}", timeout=10)
        soup = BeautifulSoup(resp.text, 'html.parser')
        # Query parameters from links
        for link in soup.find_all('a', href=True):
            if '?' in link['href']:
                parts = link['href'].split('?')
                if len(parts) > 1:
                    for pair in parts[1].split('&'):
                        if '=' in pair:
                            params['query'].append(pair.split('=')[0])
        # Form fields
        for form in soup.find_all('form'):
            for input_tag in form.find_all('input'):
                if input_tag.get('name'):
                    params['form'].append(input_tag['name'])
    except:
        pass
    # Remove duplicates
    return {k: list(set(v)) for k, v in params.items()}