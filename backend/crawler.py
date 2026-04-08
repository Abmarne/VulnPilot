import requests
from bs4 import BeautifulSoup
from typing import List, Optional, Dict, Any
from urllib.parse import urljoin, urlparse

class ReconCrawler:
    def __init__(self, target_url: str, session_cookie: Optional[str] = None):
        self.target_url = target_url.rstrip('/')
        self.base_netloc = urlparse(self.target_url).netloc
        self.session = requests.Session()
        
        # Inject custom session cookie to test authenticated routes
        if session_cookie:
            self.session.headers.update({"Cookie": session_cookie})
            
    def map_surface(self) -> Dict[str, Any]:
        """
        Crawls the target URL and returns a list of discovered endpoints, forms,
        and JavaScript file URLs.
        """
        discovered = []
        js_urls = set()
        visited = {self.target_url}
        discovered.append({"url": self.target_url, "method": "GET", "params": [], "form_fields": []})
        
        print(f"Starting Discovery on {self.target_url}...")
        try:
            response = self.session.get(self.target_url, timeout=10)
            
            if 'text/html' in response.headers.get('Content-Type', ''):
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # 1. Extract Links
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = urljoin(self.target_url + "/", href)
                    if urlparse(full_url).netloc != self.base_netloc:
                        continue
                    
                    if full_url and full_url not in visited:
                        visited.add(full_url)
                        discovered.append({"url": full_url, "method": "GET", "params": [], "form_fields": []})
                        
                # 2. Extract Forms
                for form in soup.find_all('form', action=True):
                    action = form['action']
                    method = form.get('method', 'GET').upper()
                    full_url = urljoin(self.target_url + "/", action)
                    if urlparse(full_url).netloc != self.base_netloc:
                        continue
                    
                    form_fields = [i.get('name') for i in form.find_all('input') if i.get('name')]
                    
                    # Store or update the endpoint
                    existing = next((d for d in discovered if d["url"] == full_url), None)
                    if existing:
                        existing["method"] = method
                        existing["form_fields"] = form_fields
                    else:
                        discovered.append({"url": full_url, "method": method, "params": [], "form_fields": form_fields})

                # 3. Extract Script Tags (For Semantic Reconstruction)
                for script in soup.find_all('script', src=True):
                    src = script['src']
                    js_url = urljoin(self.target_url + "/", src)
                    if urlparse(js_url).netloc != self.base_netloc:
                        continue
                    
                    if js_url:
                        js_urls.add(js_url)

        except requests.exceptions.RequestException as e:
            print(f"Error crawling {self.target_url}: {e}")
            
        print(f"Discovered {len(discovered)} endpoints and {len(js_urls)} scripts.")
        return {"endpoints": discovered, "js_urls": list(js_urls)}

    def fetch_js_content(self, js_url: str) -> str:
        """Downloads the content of a JavaScript file."""
        try:
            response = self.session.get(js_url, timeout=10)
            if response.status_code == 200:
                return response.text
        except:
            pass
        return ""

if __name__ == "__main__":
    # Test script locally
    crawler = ReconCrawler("http://example.com")
    data = crawler.map_surface()
    for ep in data["endpoints"]:
        print(ep)
