# Ni Scam Ke? 100-Case Testing Kit

Use this kit to collect repeatable hackathon evidence without visiting real scam links.

The dataset has 100 labelled cases:

- 50 expected `ALLOW` cases using official or clearly legitimate domains.
- 50 expected `BLOCK` cases using synthetic lookalike domains such as `.test`, `.site`, `.online`, and `.click`.

The synthetic suspicious URLs are only sent as text to the scanner. They are not real scam links and do not need to resolve in a browser.

## Run

Start the backend first:

```powershell
.\mvnw spring-boot:run
```

In another terminal, run:

```powershell
.\testing\run-100-scan-tests.ps1
```

The script writes a timestamped CSV into:

```text
testing\results\
```

## What To Put In The Report

Use the summary printed by the script:

- Accuracy
- True positives: synthetic scam links correctly blocked
- True negatives: legitimate links correctly allowed
- False positives: legitimate links incorrectly blocked
- False negatives: synthetic scam links missed

This is enough to show judges that you tested both safety and detection behavior, even without real scam links.
