# feature.py
import re
import socket
import ssl
from urllib.parse import urlparse, parse_qs
from datetime import datetime
try:
    # recommended: pip install requests beautifulsoup4
    import requests
    from bs4 import BeautifulSoup
    HAS_REQUESTS = True
except Exception:
    HAS_REQUESTS = False

SUSPICIOUS_WORDS = {
    "verify","account","bank","update","password","login","click","secure",
    "confirm","urgent","immediately","billing","limited","payment","suspend",
    "validate","identity","security","request","win","prize","free","gift"
}

# List of feature column names expected (match your dataset)
FEATURE_COLS = [
    "having_IP_Address","URL_Length","Shortining_Service","having_At_Symbol",
    "double_slash_redirecting","Prefix_Suffix","having_Sub_Domain","SSLfinal_State",
    "Domain_registeration_length","Favicon","port","HTTPS_token","Request_URL",
    "URL_of_Anchor","Links_in_tags","SFH","Submitting_to_email","Abnormal_URL",
    "Redirect","on_mouseover","RightClick","popUpWidnow","Iframe","age_of_domain",
    "DNSRecord","web_traffic","Page_Rank","Google_Index","Links_pointing_to_page",
    "Statistical_report"
]

class FeatureExtraction:
    def __init__(self, url=None, headers_text=None, subject=None, body=None, raw_email=None):
        """
        Provide either:
          - url (string) to extract URL features
          - raw_email (string) to parse headers+body and extract email features + first URL features
          - or headers_text, subject, body, and optional url
        """
        self.url = url or ""
        self.headers_text = headers_text or ""
        self.subject = subject or ""
        self.body = body or ""
        if raw_email and not (self.headers_text or self.subject or self.body):
            parsed = self._parse_raw_email(raw_email)
            self.headers_text = parsed.get("headers","")
            self.subject = parsed.get("subject","")
            self.body = parsed.get("body","")
        # If body contains a link, optionally set as url to extract URL features
        if not self.url:
            first_link = self._extract_first_link(self.body)
            if first_link:
                self.url = first_link

        # Normalize a parsed netloc
        if self.url:
            p = urlparse(self.url if self.url.startswith("http") else "http://" + self.url)
            self.netloc = p.netloc.lower()
            self.path = p.path or ""
            self.scheme = p.scheme or "http"
            self.query = p.query or ""
        else:
            self.netloc = ""
            self.path = ""
            self.scheme = ""
            self.query = ""

        # If requests available, attempt one request to collect page content for some features
        self.page_text = ""
        self.page_soup = None
        if HAS_REQUESTS and self.url:
            try:
                r = requests.get(self.url, timeout=5, allow_redirects=True)
                self._status_code = r.status_code
                self.page_text = r.text or ""
                self.page_soup = BeautifulSoup(self.page_text, "html.parser")
            except Exception:
                self._status_code = None

    # ---------- helpers ----------
    def _parse_raw_email(self, raw):
        parts = re.split(r"\r?\n\r?\n", raw, maxsplit=1)
        headers = parts[0] if parts else ""
        body = parts[1] if len(parts)>1 else ""
        subj = ""
        m = re.search(r"(?im)^subject:\s*(.+)$", headers)
        if m:
            subj = m.group(1).strip()
        return {"headers": headers, "subject": subj, "body": body}

    def _extract_first_link(self, text):
        if not text:
            return ""
        m = re.search(r"https?://[^\s'\"<>]+", text)
        if m:
            return m.group(0)
        # fallback to href="..."
        m2 = re.search(r'href=["\'](http[s]?://[^"\']+)["\']', text, re.I)
        if m2:
            return m2.group(1)
        return ""

    def _is_ip(self, host):
        try:
            socket.inet_aton(host)
            return True
        except:
            return False

    # ---------- URL features (approximate) ----------
    def having_IP_Address(self):
        host = self.netloc.split(':')[0]
        return -1 if host and self._is_ip(host) else 1

    def URL_Length(self):
        L = len(self.url)
        if L < 54: return 1
        if 54 <= L <= 75: return 0
        return -1

    def Shortining_Service(self):
        # common shorteners
        short = re.search(r"(bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co|short\.ly|buff\.ly)", self.url, re.I)
        return -1 if short else 1

    def having_At_Symbol(self):
        return -1 if "@" in self.url else 1

    def double_slash_redirecting(self):
        # count of '//' occurrences beyond the protocol part
        return -1 if self.url.count("//") > 1 else 1

    def Prefix_Suffix(self):
        return -1 if "-" in (self.netloc or "") else 1

    def having_Sub_Domain(self):
        host = self.netloc.split(':')[0]
        if not host: return 1
        dots = host.count('.')
        if dots <= 1: return 1
        if dots == 2: return 0
        return -1

    def SSLfinal_State(self):
        # quick check: https scheme and reachable on 443
        if self.scheme == "https":
            try:
                # try simple ssl handshake
                hostname = self.netloc.split(':')[0]
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                    s.settimeout(3)
                    s.connect((hostname, 443))
                    s.getpeercert()
                return 1
            except Exception:
                return -1
        return -1

    def Domain_registeration_length(self):
        # placeholder: requires whois; default to 1 (safe)
        return 1

    def Favicon(self):
        # if HTML content and favicon domain different => suspicious
        try:
            if self.page_soup:
                fav = self.page_soup.find("link", rel=re.compile("icon", re.I))
                if fav and fav.get("href"):
                    href = fav.get("href")
                    if self.netloc not in href:
                        return -1
            return 1
        except:
            return 1

    def port(self):
        # non-standard ports suspicious (detect :port in netloc)
        return -1 if ":" in self.netloc and not self.netloc.endswith(":80") else 1

    def HTTPS_token(self):
        # token 'https' in domain is suspicious
        return -1 if "https" in (self.netloc or "").lower() else 1

    def Request_URL(self):
        # proportion of images loaded from same domain
        try:
            if not self.page_soup:
                return -1
            imgs = self.page_soup.find_all("img", src=True)
            total = len(imgs)
            if total==0: return 1
            same = sum(1 for img in imgs if self.netloc in img.get("src",""))
            return 1 if (same/total)>0.5 else -1
        except:
            return -1

    def URL_of_Anchor(self):
        try:
            if not self.page_soup:
                return -1
            anchors = self.page_soup.find_all("a", href=True)
            total = len(anchors)
            if total==0: return 1
            same = sum(1 for a in anchors if self.netloc in a.get("href",""))
            return 1 if (same/total)>0.5 else -1
        except:
            return -1

    def Links_in_tags(self):
        # rough heuristic: many links in tags = suspicious
        try:
            if not self.page_soup: return 1
            links = self.page_soup.find_all(["link","script"], href=True)
            return -1 if len(links)>10 else 1
        except:
            return 1

    def SFH(self):
        # server form handler: check forms with action attribute
        try:
            if not self.page_soup: return 1
            forms = self.page_soup.find_all("form", action=True)
            if not forms: return 1
            for f in forms:
                action = f.get("action","")
                if action.startswith("http") and self.netloc not in action:
                    return -1
            return 1
        except:
            return 1

    def Submitting_to_email(self):
        # if any form uses mailto
        try:
            if self.page_soup and self.page_soup.find("a", href=re.compile(r"mailto:", re.I)):
                return -1
            return 1
        except:
            return 1

    def Abnormal_URL(self):
        # domain contains 'http' string etc
        return -1 if re.search(r"http@", self.netloc) else 1

    def Redirect(self):
        # consider redirects: if page had multiple // or request timed out consider suspicious
        if self._redirect_count() > 1:
            return -1
        return 1

    def _redirect_count(self):
        # naive: count '>' or number of 'redirect' substrings
        return self.url.count("redirect") + self.url.count("redirecting") 

    def on_mouseover(self):
        # searching for onmouseover JS in page
        try:
            if self.page_text and re.search(r"onmouseover", self.page_text, re.I):
                return -1
            return 1
        except:
            return 1

    def RightClick(self):
        # check for contextmenu disabling scripts
        try:
            if self.page_text and re.search(r"contextmenu", self.page_text, re.I):
                return -1
            return 1
        except:
            return 1

    def popUpWidnow(self):
        # check for window.open in JS
        try:
            if self.page_text and re.search(r"window\.open\(", self.page_text):
                return -1
            return 1
        except:
            return 1

    def Iframe(self):
        try:
            if self.page_soup and self.page_soup.find_all("iframe"):
                return -1
            return 1
        except:
            return 1

    def age_of_domain(self):
        # placeholder: requires whois; return safe
        return 1

    def DNSRecord(self):
        try:
            socket.gethostbyname(self.netloc.split(':')[0])
            return 1
        except:
            return -1

    def web_traffic(self):
        # placeholder; return neutral
        return 1

    def Page_Rank(self):
        return 1

    def Google_Index(self):
        return 1

    def Links_pointing_to_page(self):
        # placeholder
        return 1

    def Statistical_report(self):
        # if URL contains common brand keywords suspicious
        if re.search(r"(paypal|ebay|bank|amazon|microsoft)", (self.url or ""), re.I):
            return -1
        return 1

    # ---------- Email/content features ----------
    def suspicious_words_count(self, text):
        if not text: return 0
        text_l = text.lower()
        return sum(1 for w in SUSPICIOUS_WORDS if w in text_l)

    def header_spf_pass(self):
        h = (self.headers_text or "").lower()
        return 1 if "spf=pass" in h or "received-spf: pass" in h else 0

    def header_dkim(self):
        h = (self.headers_text or "").lower()
        return 1 if "dkim=" in h else 0

    def num_links_in_body(self):
        if not self.body: return 0
        return len(re.findall(r"https?://", self.body))

    # ---------- Combined extraction ----------
    def extract_all(self):
        """Return (numeric_dict, text) where numeric_dict has exactly FEATURE_COLS keys"""
        num = {}
        # URL-based features (if url empty, these functions still return defaults)
        num["having_IP_Address"] = self.having_IP_Address()
        num["URL_Length"] = self.URL_Length()
        num["Shortining_Service"] = self.Shortining_Service()
        num["having_At_Symbol"] = self.having_At_Symbol()
        num["double_slash_redirecting"] = self.double_slash_redirecting()
        num["Prefix_Suffix"] = self.Prefix_Suffix()
        num["having_Sub_Domain"] = self.having_Sub_Domain()
        num["SSLfinal_State"] = self.SSLfinal_State()
        num["Domain_registeration_length"] = self.Domain_registeration_length()
        num["Favicon"] = self.Favicon()
        num["port"] = self.port()
        num["HTTPS_token"] = self.HTTPS_token()
        num["Request_URL"] = self.Request_URL()
        num["URL_of_Anchor"] = self.URL_of_Anchor()
        num["Links_in_tags"] = self.Links_in_tags()
        num["SFH"] = self.SFH()
        num["Submitting_to_email"] = self.Submitting_to_email()
        num["Abnormal_URL"] = self.Abnormal_URL()
        num["Redirect"] = self.Redirect()
        num["on_mouseover"] = self.on_mouseover()
        num["RightClick"] = self.RightClick()
        num["popUpWidnow"] = self.popUpWidnow()
        num["Iframe"] = self.Iframe()
        num["age_of_domain"] = self.age_of_domain()
        num["DNSRecord"] = self.DNSRecord()
        num["web_traffic"] = self.web_traffic()
        num["Page_Rank"] = self.Page_Rank()
        num["Google_Index"] = self.Google_Index()
        num["Links_pointing_to_page"] = self.Links_pointing_to_page()
        num["Statistical_report"] = self.Statistical_report()

        # Add email-specific signals appended to text (model uses numeric features only,
        # but adding counts into "text" may be useful if you adapt model to include text vector)
        text_parts = []
        if self.subject:
            text_parts.append(self.subject)
        if self.body:
            text_parts.append(self.body)
        if self.url:
            text_parts.append(self.url)
        # Add headers signals (optional)
        text_parts.append(f"spf_pass:{self.header_spf_pass()}")
        text_parts.append(f"dkim:{self.header_dkim()}")
        text_parts.append(f"suspicious_words:{self.suspicious_words_count(self.subject)+self.suspicious_words_count(self.body)}")
        text = " ".join([p for p in text_parts if p])

        # Ensure ordering keys match FEATURE_COLS
        ordered_num = {k: num.get(k, 0) for k in FEATURE_COLS}
        return ordered_num, text
