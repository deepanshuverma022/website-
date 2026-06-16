# Website Security Auditor API

A production-ready FastAPI application that performs a comprehensive security audit on a target website. It analyzes SSL certificates, HTTP security headers, and DNS records (SPF, DMARC, DNSSEC) to generate a security score from 0-100, along with detailed findings and recommendations.

This API exposes OpenAPI documentation (`/openapi.json`), making it perfectly suited for direct integration into OpenAI Agent Builder as a custom tool.

## Features
- **SSL/TLS Analysis**: Verifies HTTPS, certificate validity, issuer, and expiration date.
- **HTTP Header Inspection**: Checks for `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`.
- **Cookie Security**: Identifies missing `Secure`, `HttpOnly`, or `SameSite` flags.
- **DNS Security**: Validates the presence of SPF, DMARC, and DNSSEC (DNSKEY) records.
- **Security Score Calculation**: Deducts points based on missing headers, misconfigurations, or high-risk vulnerabilities, returning a risk level (Low, Medium, High).

## Prerequisites
- Python 3.9+
- `pip`

## Running Locally

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Start the API:**
   ```bash
   uvicorn main:app --reload
   ```

3. **Access the Documentation:**
   - Swagger UI: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
   - OpenAPI Schema: [http://127.0.0.1:8000/openapi.json](http://127.0.0.1:8000/openapi.json)

## API Usage

### `POST /scan`

**Request Body:**
```json
{
  "url": "https://example.com"
}
```

**Response Example:**
```json
{
  "url": "https://example.com",
  "security_score": 85,
  "risk_level": "Low",
  "checks": {
      "https_enabled": true,
      "ssl_cert_valid": true,
      "hsts": true,
      "csp": false
  },
  "issues": [
      {
          "severity": "Medium",
          "title": "Missing Content Security Policy",
          "description": "The Content-Security-Policy header is missing.",
          "recommendation": "Implement CSP to mitigate XSS and data injection attacks."
      }
  ]
}
```

## Integrating with OpenAI Agent Builder
1. Ensure your API is deployed and publicly accessible.
2. In the OpenAI Agent Builder, go to **Actions** -> **Add Action**.
3. Import the schema by providing the URL to your OpenAPI spec (e.g., `https://your-app.onrender.com/openapi.json`).
4. OpenAI will automatically parse the `/scan` endpoint and use it as a tool.

## Deployment on Render

This project is ready to be deployed on [Render.com](https://render.com/).

1. Push this repository to GitHub/GitLab.
2. Log in to Render and click **New** -> **Web Service**.
3. Connect your repository.
4. Use the following settings:
   - **Environment**: Python
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
5. Click **Create Web Service**. Render will automatically provision the server, build the application, and provide you with a public HTTPS URL.
