import urllib.request
import asyncio
from typing import List, Dict

class URLRedirectResolver:
    def __init__(self, max_depth: int = 5, timeout_sec: float = 1.5):
        self.max_depth = max_depth
        self.timeout_sec = timeout_sec
        self.cache: Dict[str, List[str]] = {}

    async def resolve(self, url: str) -> List[str]:
        """
        Traces a redirect chain asynchronously using thread pool execution for network requests.
        """
        if url in self.cache:
            return self.cache[url]
            
        # Run blocking resolver in thread pool using asyncio.to_thread
        chain = await asyncio.to_thread(self._trace_redirects_sync, url)
        self.cache[url] = chain
        return chain

    def _trace_redirects_sync(self, url: str) -> List[str]:
        chain = [url]
        visited = {url}
        curr_url = url
        
        # Helper custom redirect handler to intercept intermediate hops
        class CustomRedirectHandler(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, hdrs, newurl):
                # Record hop
                nonlocal curr_url
                curr_url = newurl
                return super().redirect_request(req, fp, code, msg, hdrs, newurl)

        # Build custom opener
        opener = urllib.request.build_opener(CustomRedirectHandler())
        
        for _ in range(self.max_depth):
            try:
                # Prefer HTTP HEAD request
                req = urllib.request.Request(
                    curr_url, 
                    method="HEAD",
                    headers={"User-Agent": "MailArmour-Security-Scanner/2.0.0"}
                )
                
                with opener.open(req, timeout=self.timeout_sec) as response:
                    final_url = response.geturl()
                    if final_url != curr_url:
                        if final_url in visited:
                            # Redirect loop detected
                            chain.append(final_url)
                            break
                        visited.add(final_url)
                        chain.append(final_url)
                        curr_url = final_url
                    else:
                        break
            except Exception:
                # Fallback to GET request if HEAD is blocked/unsupported
                try:
                    req_get = urllib.request.Request(
                        curr_url,
                        method="GET",
                        headers={"User-Agent": "MailArmour-Security-Scanner/2.0.0"}
                    )
                    with opener.open(req_get, timeout=self.timeout_sec) as response:
                        final_url = response.geturl()
                        if final_url != curr_url:
                            if final_url in visited:
                                chain.append(final_url)
                                break
                            visited.add(final_url)
                            chain.append(final_url)
                            curr_url = final_url
                        else:
                            break
                except Exception:
                    # Network connection failure or host offline, abort
                    break
                    
        return chain
