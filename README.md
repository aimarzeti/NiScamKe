# Ni Scam Ke?

Ni Scam Ke? is a Malaysian anti-scam browser protection prototype for Hackathon X Fintech Forward 2026. It scans links and page text, explains risk decisions, blocks high-risk phishing pages, and lets users report false positives for human review.

## Problem

Malaysian users are frequently targeted by fake banking, parcel, investment, and OTP-harvesting links. Many victims only realise something is wrong after they have entered credentials. Ni Scam Ke? intervenes before that moment by giving a clear risk signal inside the browser.

## Solution

- Chrome extension scans the current page URL and visible text.
- Spring Boot backend returns `ALLOW`, `WARN`, or `BLOCK` decisions.
- Risk decisions include a score, confidence, reasons, evidence sources, and a decision ID.
- High-risk pages are replaced with a safe warning page.
- Users can report false positives.
- Review dashboard lets moderators approve safe sites or reject reports.
- Live dashboard shows scan counts and recent decisions for demo visibility.

## Technology Used

- Java 21
- Spring Boot 3.2
- Spring Web
- Spring Data JPA
- Flyway database migrations
- H2 in-memory database for local demo
- Google Gemini API for AI-assisted phishing analysis
- Chrome Extension Manifest V3
- PowerShell testing kit with 100 labelled scan cases

## Project Structure

```text
src/main/java/com/niscamke/backend
  controller/      REST API endpoints
  service/         risk scoring, AI integration, reporting workflow
  repository/      JPA repositories
  model/           database entities

src/main/resources
  db/migration/    Flyway schema migrations
  static/          dashboard and false-positive review UI

src/main/extension
  manifest.json    Chrome extension manifest
  background.js    live backend scan + local fallback rules
  content.js       page scanner and blocker trigger
  popup.*          user-facing extension popup
  blocked.*        high-risk warning and false-positive report flow

testing
  test-cases-100.csv
  run-100-scan-tests.ps1
```

## Local Setup

1. Install Java 21.
2. Set the Gemini key only in your local environment:

```powershell
$env:GEMINI_API_KEY="your-gemini-api-key"
```

3. Start the backend:

```powershell
.\mvnw spring-boot:run
```

4. Open the judge dashboard:

```text
http://localhost:8080/dashboard.html
```

5. Load the Chrome extension:

- Open Chrome Extensions.
- Enable Developer Mode.
- Click Load unpacked.
- Select `src/main/extension`.

## Demo Flow

1. Start the backend on `localhost:8080`.
2. Open `http://localhost:8080/dashboard.html`.
3. Load or reload the Chrome extension from `src/main/extension`.
4. Open `http://localhost:8080/demo.html`.
5. Point out that the extension badge updates automatically after the page scan.
6. Click the synthetic scam link: `https://maybank-secure-login.test/verify-account?otp=required`.
7. Show that Ni Scam Ke? blocks the URL before the browser reaches the fake site.
8. Show the blocked page, risk score, reasons, and false-positive report form.
9. Return to the dashboard to show the new `BLOCK` decision in recent decisions.
10. Submit a false-positive report, open `http://localhost:8080/review.html`, and approve or reject it.

## Pitch Proof Checklist

- Automatic scan: open `demo.html`, then open the extension popup. It should already show the current tab's scan result without pressing a scan button.
- Badge signal: the extension icon shows `OK`, `!`, or `STOP` based on the latest tab decision.
- Pre-click blocking: clicking the synthetic scam link is intercepted and scanned before navigation.
- Direct URL blocking: paste `maybank-secure-login.test/verify-account?otp=required` into the address bar. The extension preflights the top-level navigation and redirects to the blocked page before Chrome's DNS error becomes the final user experience.
- Credential-entry guard: focusing the fake password or OTP field triggers an extra protection refresh.
- Evidence trail: `dashboard.html` shows the recent `ALLOW`, `WARN`, and `BLOCK` decisions for judges.

## Testing Evidence

Run the 100-case test kit after the backend is running:

```powershell
.\testing\run-100-scan-tests.ps1
```

The script writes timestamped CSV results into `testing/results/` and prints:

- Accuracy
- True positives
- True negatives
- False positives
- False negatives

## API Summary

- `POST /api/v1/scan-url` scans a URL and page text.
- `POST /api/v1/report-url` submits a community scam report.
- `POST /api/v1/false-positive` submits a false-positive review request.
- `GET /api/v1/false-positive?status=PENDING_REVIEW` lists review items.
- `PATCH /api/v1/false-positive/{id}/status` approves or rejects a report.
- `GET /api/v1/admin/summary` returns dashboard counts.
- `GET /api/v1/admin/recent-decisions` returns recent scan decisions.
- `GET /api/v1/health` checks backend health.

## Privacy and Safety Notes

- Ni Scam Ke? never asks for passwords, OTPs, PINs, or banking credentials.
- Demo scam URLs should be synthetic and do not need to resolve.
- The Gemini API key is not committed. Use the `GEMINI_API_KEY` environment variable.
- If the backend is offline, the extension uses local fallback rules and clearly labels that state.

## AI Tools Used

- Google Gemini API is used as part of the scam/phishing analysis pipeline.
- AI-assisted development tools were used during hackathon implementation and debugging.
- Team members must be able to explain the code, architecture, prompts, and tradeoffs during Q&A.

## Business and Impact Angle

Ni Scam Ke? can support banks, fintech apps, universities, and public-sector awareness campaigns by reducing scam exposure before credential entry. The product can grow through bank-backed domain intelligence, community reporting, moderator review, and enterprise protection analytics.
