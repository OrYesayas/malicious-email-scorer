# Malicious Email Scorer — Gmail Add-on

> Work in progress. This README will be completed with the architecture,
> design decisions, trade-offs and setup guide.

A Gmail Add-on that analyzes the opened email and shows a maliciousness score,
a verdict, and the reasons behind it.

## Repository layout

```
addon/      Google Apps Script add-on (UI, extraction, signed calls to backend)
backend/    Python FastAPI service (analyzers, scoring), deployed on Cloud Run
```

## Running the backend tests

```bash
cd backend
pip install -r requirements-dev.txt
pytest
```
