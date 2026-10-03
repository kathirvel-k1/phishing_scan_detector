# PhishGuard

PhishGuard is a responsive phishing and scam message detector demo. Paste a text message, email, or URL to get a risk level, score, detected warning signs, URL checks, and safer next steps.

## Project structure

```text
science_expo/
├── app/
│   ├── __init__.py
│   ├── ai_agent.py       # Optional OpenAI Responses API integration
│   ├── analyzer.py       # Explainable message and URL signal analysis
│   ├── main.py           # FastAPI app and API routes
│   ├── schemas.py        # Validated request and response models
│   ├── text_model.py     # Dependency-free Naive Bayes demo classifier
│   └── static/
│       ├── index.html    # Responsive interface
│       ├── app.css       # Layout, visual styles, and motion
│       └── app.js        # UI behavior and API integration
├── .env.example          # OpenAI configuration template
├── .gitignore
├── README.md
└── requirements.txt
```

The separate chat-style demo agent page is `app/static/agent.html` and is served at `/agent` when FastAPI is running. Its fictional sample emails cover account verification, prize bait, delivery fees, a lookalike URL, and a routine meeting update. It uses `POST /api/demo/analyze`, which always runs the local simulation. The main checker uses `POST /api/analyze` and can use OpenAI when configured.

## Run locally

Requires Python 3.10 or newer.

```bash
python -m venv .venv
```

Activate the environment, then install and start the app:

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open <http://127.0.0.1:8000>. The chat-style demo agent is at <http://127.0.0.1:8000/agent>. The API documentation is available at <http://127.0.0.1:8000/docs>.

## Enable the OpenAI AI agent

The app runs a local Demo AI agent without an API key. It uses the bundled Naive Bayes text model and explainable URL checks. To enable OpenAI analysis instead, copy `.env.example` to `.env`, then replace the placeholder with your API key:

```powershell
Copy-Item .env.example .env
```

```env
OPENAI_API_KEY=your_real_key_here
OPENAI_MODEL=gpt-6-astra
```

Keep `.env` private and never put the key in frontend JavaScript or commit it. The backend reads `.env` when checking its health and analyzing a message, so refresh the page after saving the key. When configured, the report combines OpenAI's structured message analysis with the local URL checks. If the API is unavailable, the local analyzer is used as a fallback. The interface indicates which analysis mode is active and discloses when message text is sent to OpenAI.

## How the analysis works

Without an API key, the Demo AI agent combines a small Multinomial Naive Bayes text model with explainable checks. With an OpenAI API key, the Responses API supplies structured message analysis, while visible URL characteristics are still checked locally. Neither mode opens URLs or verifies senders. Evidence is returned with each result so the risk score is explainable.

This is an educational demo, and the bundled Naive Bayes examples are too small to represent real-world scam language. The model is a learning baseline, not a production detector. In OpenAI mode, message text is sent to OpenAI for analysis. The app does not open or reputation-check URLs, and a low score cannot establish that a message is safe.

## API

`POST /api/analyze`

```json
{
  "message": "Your account is suspended. Verify your password at http://example.com"
}
```

`GET /api/health` returns a simple health status.
