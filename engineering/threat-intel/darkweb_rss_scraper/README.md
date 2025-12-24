# Dark Web RSS Monitor

A specialized threat intelligence tool that scrapes RSS feeds from dark web hacking forums to find mentions of specific corporate keywords.

### How it works
This script identifies new forum threads and leak listings by parsing XML feeds via the Tor network. It is significantly stealthier than traditional web scraping because it requests only a few hundred lines of XML rather than full HTML pages with tracking scripts.

### Requirements
*   **Python 3.x**
*   **Tor Service:** Must be running locally (Port 9050 or 9150).
*   **Libraries:**
    ```bash
    pip install requests[socks] feedparser
    ```

### Configuration
1.  **Proxies:** If using the Tor Browser instead of the Tor Service, change `TOR_PROXY` to use port `9150`.
2.  **Onion Links:** Populate `TARGET_FEEDS` with current active .onion links found via directories like Ahmia.
3.  **Keywords:** Add your brand names, domains, or specific internal project titles.

### Security Note
For maximum OPSEC, run this on a dedicated Virtual Machine (VM). Ensure you do not accidentally include your own IP in the headers if you modify the user-agent.

### Common RSS Feed URL Patterns

Here is the formatted table. You can copy and paste this directly into your README.md under a "Supported Patterns" or "Discovery" section.
Common Forum RSS Patterns
If you find a new onion site but aren't sure where the feed is located, try appending these common suffixes to the base URL:
Software	RSS URL Pattern	Notes
XenForo	/forums/-/index.rss	Used by XSS.is, Dread, and most modern dark web forums.
vBulletin	/external.php?type=RSS2	Common on older, high-profile Russian forums like Exploit.in.
MyBB	/syndication.php?limit=20	The default for BreachForums and many of its clones/variants.
Invision (IPB)	/index.php?app=core&module=global&section=rss	Found on several private data leak and "VIP" sites.
WordPress	/feed/ or /?feed=rss2	Standard for ransomware "wall of shame" blogs and news sites.
Simple Machines	/?type=rss;action=.xml	Used by some smaller, niche technical hacking communities.
How to use these
If a site is located at http://example777.onion, try accessing http://example777.onion/syndication.php in the Tor Browser first. If you see an XML page (text that looks like code), that is the URL you should add to the TARGET_FEEDS list in the script
