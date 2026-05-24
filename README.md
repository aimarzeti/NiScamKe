# Ni Scam Ke?

Ni Scam Ke? is a Malaysian anti-scam browser protection prototype. The idea is simple: before someone clicks a suspicious link or enters an OTP/password, the browser checks the page, asks the backend for a risk decision, and blocks the page if the risk is high.

## The Problem

Many scam victims only realise something is wrong after they already entered banking details, OTP/TAC codes, phone numbers, or personal information. Malaysian users also face a lot of lookalike banking links, fake aid/reward application links, parcel scams, and investment scams.

Problem statement:
> How can we warn users before they trust a scam link, not after the damage is done?

## Our Solution

Ni Scam Ke? works as a browser protection layer with a Spring Boot backend.

- The Chrome extension scans the current URL and visible page text.
- The backend extracts URL and content risk features.
- Gemini AI gives an extra phishing/scam analysis when an API key is configured.
- The system returns `ALLOW`, `WARN`, or `BLOCK`.
- High-risk pages are redirected to a safer warning page.
- Users can submit a false-positive report if a blocked site is actually safe.
- A review dashboard lets a moderator approve or reject false-positive reports.
- A command center dashboard shows scan counts, recent threats, and service health.

## Is It Just Constants?

No. The prototype is not only based on fixed constants.

There are local rules and trusted-domain lists, but they are used as safety signals and fallback protection. The main backend scan flow is:

1. Parse and normalise the URL.
2. Extract scam features like high-risk TLD, typo-like bank domains, credential keywords, fake aid/reward bait, and suspicious application routes.
3. Call Google Gemini through `GeminiIntegrationService` when `GEMINI_API_KEY` is configured.
4. Ask Gemini for a structured scam verdict and explanation.
5. Combine AI output with the rule-based score.
6. Save the decision with risk score, confidence, evidence source, threat type, explanation, and decision ID.

If the Gemini key is missing or the backend cannot reach Gemini, the prototype still runs using local rules. That is intentional because a protection tool should fail safely during a demo or network problem. 

## What Works Now

- Live backend API for URL scanning.
- Gemini AI integration with structured prompt, JSON parsing, and retry for temporary Gemini failures.
- Rule-based URL feature extraction for Malaysian scam patterns.
- Chrome extension popup with automatic page scan status.
- Badge signal for safe, warning, and blocked pages.
- Pre-click link scanning before navigation.
- Direct navigation preflight blocking for obvious high-risk links.
- Credential-entry guard when password, OTP, TAC, card, or phone fields are focused.
- Blocked-page explanation with risk score, reasons, and evidence source.
- False-positive report form.
- Human review page for pending false-positive reports.
- Dashboard with scan counts and recent decisions.
- Test coverage for URL feature extraction and Gemini integration behaviour.

## Tech Stack

- Java 21
- Spring Boot 3.2
- Spring Web
- Spring Data JPA
- Flyway migrations
- H2 in-memory database for local demo
- Google Gemini API
- Chrome Extension Manifest V3
- HTML, CSS, JavaScript dashboard pages
- PowerShell testing kit with 100 labelled scan cases

## Project Structure

```text
src/main/java/com/niscamke/backend
  controller/      REST API endpoints
  service/         scan logic, Gemini integration, risk scoring, review workflow
  repository/      JPA repositories
  model/           database entities

src/main/resources
  db/migration/    Flyway database schema
  static/          dashboard, protection page, review page

src/main/extension
  manifest.json    Chrome extension setup
  background.js    backend scan, navigation preflight, local fallback
  content.js       page scanning and credential-entry guard
  popup.*          extension popup UI
  blocked.*        blocked page and false-positive form

testing
  test-cases-100.csv
  run-100-scan-tests.ps1
```

## Local Setup

1. Install Java 21.
2. Set your Gemini key locally:

```powershell
$env:GEMINI_API_KEY="your-gemini-api-key" //we provided under the secrets folder
```

3. Start the backend:

```powershell
.\mvnw.cmd spring-boot:run
```

4. Open the dashboard:

```text
http://localhost:8080/dashboard.html
```

5. Load the Chrome extension:

- Open Chrome Extensions.
- Turn on Developer Mode.
- Click Load unpacked.
- Select `src/main/extension`.

## Demo Flow

Use this flow for the judges:

1. Start the backend.
2. Open `http://localhost:8080/dashboard.html`.
3. Load or reload the Chrome extension.
4. Open `http://localhost:8080/protection.html`.
5. Show the extension badge and popup scan result.
6. Click the safe Maybank link and explain why trusted domains are allowed.
7. Go back and click the high-risk banking link:

For example,
```text
https://maybank-secure-login.test/verify-account?otp=required
```

8. Show that Ni Scam Ke? blocks the page before the user enters anything.
9. Point out the risk score, explanation, and evidence source.
10. Submit a false-positive report from the blocked page.
11. Open `http://localhost:8080/review.html` and show the human review queue.
12. Return to `dashboard.html` and show that scan activity is logged.

## Rubric Alignment

- **Functionality & Demo:** working backend, extension flow, dashboard, blocked page, and review page.
- **Code Quality & Architecture:** controller, service, repository, model, migration, and extension layers are separated.
- **UX & Visual Polish:** user gets simple labels like `ALLOW`, `WARN`, and `BLOCK`, plus a plain-language reason.
- **Business Viability:** banks, fintechs, universities, and public-sector campaigns can use it as a protection and awareness layer.
- **Presentation & Q&A:** we can explain the AI prompt, rule engine, fallback behaviour, and false-positive workflow.
- **Real-World Potential:** the prototype can scale with bank domain intelligence, community reports, and reviewer validation.

## Testing

Run the backend tests:

```powershell
.\mvnw.cmd -q test
```

Run the 100-case scan kit after the backend is running:

```powershell
.\testing\run-100-scan-tests.ps1
```

The script writes timestamped results into `testing/results/` and prints accuracy, true positives, true negatives, false positives, and false negatives.

## API Summary

- `POST /api/v1/scan-url` scans a URL and page text.
- `POST /api/v1/report-url` submits a community scam report.
- `POST /api/v1/false-positive` submits a false-positive review request.
- `GET /api/v1/false-positive?status=PENDING_REVIEW` lists review items.
- `PATCH /api/v1/false-positive/{id}/status` approves or rejects a report.
- `GET /api/v1/admin/summary` returns dashboard counts.
- `GET /api/v1/admin/recent-decisions` returns recent scan decisions.
- `GET /api/v1/stats/dashboard` returns dashboard stats and service health.
- `GET /api/v1/health/detailed` checks backend health and Gemini configuration.

## Privacy And Safety Notes

- Ni Scam Ke? never asks users for passwords, OTPs, TAC codes, PINs, or banking credentials.
- The demo scam URLs use controlled high-risk examples and do not need to resolve.
- The Gemini API key is not committed. Use `GEMINI_API_KEY` locally.
- If the backend is offline, the extension uses local fallback rules so the demo still has a safety layer.

## AI Tools Used

- Google Gemini API is integrated into the scam/phishing analysis pipeline.
- AI-assisted development tools were used during the hackathon to help with implementation, debugging, README wording, and verification.
- We still need to understand and explain our own code, especially the scan flow, Gemini prompt, fallback rules, and review workflow.

## What We Would Improve Next

- Add more labelled Malaysian scam datasets.
- Store reviewer decisions in a persistent production database.
- Add bank/fintech partner feeds for official domain intelligence.
- Improve multilingual explanations for Bahasa Malaysia, Mandarin, and Tamil.
- Add role-based login for reviewers.
- Tune thresholds using real false-positive and false-negative feedback.
