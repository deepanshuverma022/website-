import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse
import dns.resolver
import requests
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field
from typing import List, Dict, Any

app = FastAPI(
    title="Website Security Auditor API",
    description="API to perform comprehensive security audits on target websites. Suitable for integration with OpenAI Agent Builder.",
    version="1.0.0",
    docs_url="/docs",
    openapi_url="/openapi.json"
)

class ScanRequest(BaseModel):
    url: str = Field(..., description="The full URL to audit, e.g., 'https://example.com'")

class Issue(BaseModel):
    severity: str
    title: str
    description: str
    recommendation: str

class ScanResponse(BaseModel):
    url: str
    security_score: int
    risk_level: str
    checks: Dict[str, Any]
    issues: List[Issue]

# Helper to extract hostname from URL
def get_hostname(url: str) -> str:
    parsed = urlparse(url)
    return parsed.hostname or parsed.path.split('/')[0]

def analyze_ssl(hostname: str, checks: Dict[str, Any], issues: List[Issue], points: Dict[str, int]):
    """Analyzes the SSL certificate for the given hostname."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                checks["https_enabled"] = True
                checks["ssl_cert_valid"] = True
                
                # Extract issuer
                issuer = dict(x[0] for x in cert.get('issuer', []))
                checks["ssl_cert_issuer"] = issuer.get('organizationName', issuer.get('commonName', 'Unknown'))
                
                # Check expiration
                not_after = cert.get('notAfter')
                if not_after:
                    expire_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    checks["ssl_cert_expiration_date"] = expire_date.isoformat()
                    days_left = (expire_date - datetime.utcnow()).days
                    if days_left < 30:
                        issues.append(Issue(
                            severity="Medium",
                            title="SSL Certificate Expiring Soon",
                            description=f"The SSL certificate will expire in {days_left} days.",
                            recommendation="Renew the SSL certificate before it expires."
                        ))
                        points["score"] -= 10
    except ssl.SSLCertVerificationError:
        checks["https_enabled"] = True
        checks["ssl_cert_valid"] = False
        checks["ssl_cert_issuer"] = None
        checks["ssl_cert_expiration_date"] = None
        issues.append(Issue(
            severity="High",
            title="Invalid SSL Certificate",
            description="The SSL certificate could not be verified. It may be self-signed or from an untrusted authority.",
            recommendation="Install a valid SSL certificate from a trusted Certificate Authority."
        ))
        points["score"] -= 30
    except Exception as e:
        checks["https_enabled"] = False
        checks["ssl_cert_valid"] = False
        checks["ssl_cert_issuer"] = None
        checks["ssl_cert_expiration_date"] = None
        issues.append(Issue(
            severity="Critical",
            title="HTTPS Not Enabled or Inaccessible",
            description=f"Could not connect via HTTPS.",
            recommendation="Ensure port 443 is open and a valid SSL certificate is installed."
        ))
        points["score"] -= 40

def analyze_headers(url: str, checks: Dict[str, Any], issues: List[Issue], points: Dict[str, int]):
    """Analyzes the HTTP response headers for security best practices."""
    try:
        parsed = urlparse(url)
        http_url = f"http://{parsed.netloc}{parsed.path}"
        
        # 1. Check HTTP to HTTPS redirect
        try:
            resp_http = requests.get(http_url, timeout=5, allow_redirects=False)
            if resp_http.status_code in (301, 302, 307, 308) and resp_http.headers.get('Location', '').startswith('https://'):
                checks["http_to_https_redirect"] = True
            else:
                checks["http_to_https_redirect"] = False
                issues.append(Issue(
                    severity="Medium",
                    title="Missing HTTP to HTTPS Redirect",
                    description="The server does not redirect HTTP traffic to HTTPS.",
                    recommendation="Configure the web server to redirect all HTTP traffic to HTTPS."
                ))
                points["score"] -= 10
        except requests.RequestException:
            checks["http_to_https_redirect"] = False

        # 2. Request actual URL via HTTPS to analyze headers
        https_url = f"https://{parsed.netloc}{parsed.path}"
        response = requests.get(https_url, timeout=10)
        headers = response.headers

        # HSTS
        if "Strict-Transport-Security" in headers:
            checks["hsts"] = True
        else:
            checks["hsts"] = False
            issues.append(Issue(
                severity="Medium",
                title="Missing HSTS Header",
                description="The Strict-Transport-Security header is not set.",
                recommendation="Enable HSTS to force browsers to use secure connections."
            ))
            points["score"] -= 10

        # CSP
        if "Content-Security-Policy" in headers:
            checks["csp"] = True
        else:
            checks["csp"] = False
            issues.append(Issue(
                severity="Medium",
                title="Missing Content-Security-Policy",
                description="The Content-Security-Policy header is missing.",
                recommendation="Implement CSP to mitigate XSS and data injection attacks."
            ))
            points["score"] -= 10

        # X-Frame-Options
        if "X-Frame-Options" in headers:
            checks["x_frame_options"] = True
        else:
            checks["x_frame_options"] = False
            issues.append(Issue(
                severity="Low",
                title="Missing X-Frame-Options",
                description="The X-Frame-Options header is not set.",
                recommendation="Set X-Frame-Options to DENY or SAMEORIGIN to prevent clickjacking."
            ))
            points["score"] -= 5

        # X-Content-Type-Options
        if "X-Content-Type-Options" in headers:
            checks["x_content_type_options"] = True
        else:
            checks["x_content_type_options"] = False
            issues.append(Issue(
                severity="Low",
                title="Missing X-Content-Type-Options",
                description="The X-Content-Type-Options header is missing.",
                recommendation="Set X-Content-Type-Options to nosniff to prevent MIME type sniffing."
            ))
            points["score"] -= 5

        # Referrer-Policy
        if "Referrer-Policy" in headers:
            checks["referrer_policy"] = True
        else:
            checks["referrer_policy"] = False
            issues.append(Issue(
                severity="Low",
                title="Missing Referrer-Policy",
                description="The Referrer-Policy header is missing.",
                recommendation="Set Referrer-Policy to control how much referrer information is included with requests."
            ))
            points["score"] -= 5

        # Permissions-Policy
        if "Permissions-Policy" in headers or "Feature-Policy" in headers:
            checks["permissions_policy"] = True
        else:
            checks["permissions_policy"] = False
            issues.append(Issue(
                severity="Low",
                title="Missing Permissions-Policy",
                description="The Permissions-Policy header is missing.",
                recommendation="Set Permissions-Policy to control which browser features are allowed to be used."
            ))
            points["score"] -= 5

        # Server Header Disclosure
        server_header = headers.get("Server")
        if server_header:
            checks["server_header_disclosure"] = True
            issues.append(Issue(
                severity="Low",
                title="Server Version Disclosure",
                description=f"The Server header reveals information about the server software: {server_header}",
                recommendation="Remove or obscure the Server header to prevent information leakage."
            ))
            points["score"] -= 5
        else:
            checks["server_header_disclosure"] = False

        # Cookies Analysis
        # We parse the raw Set-Cookie headers directly from the response
        checks["secure_cookies"] = True
        checks["httponly_cookies"] = True
        checks["samesite_cookies"] = True
        
        set_cookies = headers.get("Set-Cookie")
        if set_cookies:
            set_cookies_lower = set_cookies.lower()
            if "secure" not in set_cookies_lower:
                checks["secure_cookies"] = False
                issues.append(Issue(severity="Medium", title="Insecure Cookies", description="Cookies are set without the Secure flag.", recommendation="Add the Secure flag to all cookies."))
                points["score"] -= 5
            if "httponly" not in set_cookies_lower:
                checks["httponly_cookies"] = False
                issues.append(Issue(severity="Medium", title="Missing HttpOnly Flag", description="Cookies are set without the HttpOnly flag.", recommendation="Add the HttpOnly flag to cookies to mitigate XSS."))
                points["score"] -= 5
            if "samesite" not in set_cookies_lower:
                checks["samesite_cookies"] = False
                issues.append(Issue(severity="Low", title="Missing SameSite Attribute", description="Cookies are missing the SameSite attribute.", recommendation="Set SameSite to Strict or Lax to mitigate CSRF."))
                points["score"] -= 5

    except requests.RequestException as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Failed to connect to the target URL: {str(e)}")

def analyze_dns(hostname: str, checks: Dict[str, Any], issues: List[Issue], points: Dict[str, int]):
    """Analyzes the DNS records for the given hostname."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    # 1. SPF Record
    try:
        txt_records = resolver.resolve(hostname, 'TXT')
        spf_found = any('v=spf1' in str(record) for record in txt_records)
        checks["dns_spf_record"] = spf_found
        if not spf_found:
            issues.append(Issue(
                severity="Medium",
                title="Missing SPF Record",
                description="No Sender Policy Framework (SPF) record found.",
                recommendation="Configure an SPF record to prevent email spoofing."
            ))
            points["score"] -= 10
    except Exception:
        checks["dns_spf_record"] = False
        issues.append(Issue(severity="Medium", title="Missing SPF Record", description="No Sender Policy Framework (SPF) record found.", recommendation="Configure an SPF record to prevent email spoofing."))
        points["score"] -= 10

    # 2. DMARC Record
    try:
        dmarc_hostname = f"_dmarc.{hostname}"
        txt_records = resolver.resolve(dmarc_hostname, 'TXT')
        dmarc_found = any('v=DMARC1' in str(record) for record in txt_records)
        checks["dns_dmarc_record"] = dmarc_found
        if not dmarc_found:
            issues.append(Issue(
                severity="Medium",
                title="Missing DMARC Record",
                description="No Domain-based Message Authentication, Reporting, and Conformance (DMARC) record found.",
                recommendation="Configure a DMARC record to protect your domain from unauthorized use."
            ))
            points["score"] -= 10
    except Exception:
        checks["dns_dmarc_record"] = False
        issues.append(Issue(severity="Medium", title="Missing DMARC Record", description="No DMARC record found.", recommendation="Configure a DMARC record to protect your domain from unauthorized use."))
        points["score"] -= 10

    # 3. DNSSEC
    try:
        # Check for DNSKEY as a proxy for DNSSEC being enabled
        dnskey_records = resolver.resolve(hostname, 'DNSKEY')
        checks["dnssec_status"] = True
    except Exception:
        checks["dnssec_status"] = False
        issues.append(Issue(
            severity="Low",
            title="DNSSEC Not Enabled",
            description="DNSSEC records (DNSKEY) were not found.",
            recommendation="Enable DNSSEC on your domain to protect against DNS spoofing."
        ))
        points["score"] -= 5

@app.post("/scan", response_model=ScanResponse, summary="Scan a website for security vulnerabilities")
def scan_website(request: ScanRequest):
    url = request.url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            raise ValueError("Invalid URL structure")
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid URL provided.")

    hostname = get_hostname(url)
    
    checks = {}
    issues = []
    points = {"score": 100}

    # Perform security analysis
    try:
        analyze_ssl(hostname, checks, issues, points)
        analyze_headers(url, checks, issues, points)
        analyze_dns(hostname, checks, issues, points)
    except HTTPException as e:
        # Re-raise HTTP exceptions (like bad URL / connection failure)
        raise e
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An error occurred during the scan: {str(e)}")

    # Normalize the score (prevent negative scores)
    final_score = max(0, points["score"])

    # Determine risk level based on the final score
    if final_score >= 80:
        risk_level = "Low"
    elif final_score >= 50:
        risk_level = "Medium"
    else:
        risk_level = "High"

    return ScanResponse(
        url=url,
        security_score=final_score,
        risk_level=risk_level,
        checks=checks,
        issues=issues
    )
