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
            
    def map_surface(self) -> List[str]:
        """
        Crawls the target URL and returns a list of discovered endpoints/forms.
        """
        discovered_endpoints = set()
        discovered_endpoints.add(self.target_url)
        
        print(f"Starting Discovery on {self.target_url}...")
        try:
            response = self.session.get(self.target_url, timeout=10)
            
            # Simple content parsing if HTML
            if 'text/html' in response.headers.get('Content-Type', ''):
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract Links
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if href.startswith('/'):
                        discovered_endpoints.add(self.target_url + href)
                    elif href.startswith(self.target_url):
                        discovered_endpoints.add(href)
                        
                # Extract Forms (highly vulnerable surface)
                for form in soup.find_all('form', action=True):
                    action = form['action']
                    if action.startswith('/'):
                        discovered_endpoints.add(self.target_url + action)

        except requests.exceptions.RequestException as e:
            print(f"Error crawling {self.target_url}: {e}")
            
        print(f"Discovered {len(discovered_endpoints)} endpoints.")
        return list(discovered_endpoints)

if __name__ == "__main__":
    # Test script locally
    crawler = ReconCrawler("http://example.com")
    endpoints = crawler.map_surface()
    for ep in endpoints:
        print(ep)
