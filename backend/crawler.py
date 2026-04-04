import requests
from bs4 import BeautifulSoup
from typing import List, Optional

class ReconCrawler:
    def __init__(self, target_url: str, session_cookie: Optional[str] = None):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        
        # Inject custom session cookie to test authenticated routes
        if session_cookie:
            self.session.headers.update({"Cookie": session_cookie})
            
    def map_surface(self) -> List[Dict[str, Any]]:
        """
        Crawls the target URL and returns a list of discovered endpoints and forms.
        Each entry is a dict with {url, method, params, form_fields}.
        """
        discovered = []
        visited = {self.target_url}
        discovered.append({"url": self.target_url, "method": "GET", "params": [], "form_fields": []})
        
        print(f"Starting Discovery on {self.target_url}...")
        try:
            response = self.session.get(self.target_url, timeout=10)
            
            if 'text/html' in response.headers.get('Content-Type', ''):
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract Links
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = ""
                    if href.startswith('/'):
                        full_url = self.target_url + href
                    elif href.startswith(self.target_url):
                        full_url = href
                    
                    if full_url and full_url not in visited:
                        visited.add(full_url)
                        discovered.append({"url": full_url, "method": "GET", "params": [], "form_fields": []})
                        
                # Extract Forms (highly vulnerable surface)
                for form in soup.find_all('form', action=True):
                    action = form['action']
                    method = form.get('method', 'GET').upper()
                    full_url = self.target_url + action if action.startswith('/') else action
                    
                    form_fields = [i.get('name') for i in form.find_all('input') if i.get('name')]
                    
                    if full_url not in visited: # Don't re-visit but we might use this as a target
                        # Check if it was already discovered as a GET link
                        existing = next((d for d in discovered if d["url"] == full_url), None)
                        if existing:
                            existing["method"] = method
                            existing["form_fields"] = form_fields
                        else:
                            discovered.append({"url": full_url, "method": method, "params": [], "form_fields": form_fields})

        except requests.exceptions.RequestException as e:
            print(f"Error crawling {self.target_url}: {e}")
            
        print(f"Discovered {len(discovered)} unique targets.")
        return discovered

if __name__ == "__main__":
    # Test script locally
    crawler = ReconCrawler("http://example.com")
    endpoints = crawler.map_surface()
    for ep in endpoints:
        print(ep)
