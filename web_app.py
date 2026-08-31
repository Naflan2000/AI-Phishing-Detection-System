import os
import re
from datetime import datetime

from flask import Flask, jsonify, render_template_string, request
import joblib

DEPLOYMENT_VERSION = "2026-08-31-ML-DEBUG-01"

try:
    from url_analyzer import analyze_text_urls
except Exception as error:
    analyze_text_urls = None
    URL_ANALYZER_IMPORT_ERROR = f"{type(error).__name__}: {error}"
else:
    URL_ANALYZER_IMPORT_ERROR = ""


# ============================================================
# AI PHISHING DETECTION SYSTEM
# PREMIUM ULTRA WEB APPLICATION
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# IMPORTANT: These are the ONLY production email-model files used by Vercel.
# Do not replace them with the old/random-forest backups.
MODEL_FILENAME = "logistic_regression_model.pkl"
VECTORIZER_FILENAME = "tfidf_vectorizer_final.pkl"
URL_MODEL_FILENAME = "url_phishing_model.pkl"
URL_FEATURES_FILENAME = "url_feature_names.pkl"

MODEL_PATH = os.path.join(BASE_DIR, MODEL_FILENAME)
VECTORIZER_PATH = os.path.join(BASE_DIR, VECTORIZER_FILENAME)
URL_MODEL_PATH = os.path.join(BASE_DIR, URL_MODEL_FILENAME)
URL_FEATURES_PATH = os.path.join(BASE_DIR, URL_FEATURES_FILENAME)

app = Flask(__name__)

model = None
vectorizer = None
url_model = None
url_feature_names = None
MODEL_STATUS = "OFFLINE"
MODEL_ERROR = ""
URL_MODEL_STATUS = "OFFLINE"
URL_MODEL_ERROR = ""


def _load_pickle(path, description):
    """Load a production pickle and raise a useful error if unavailable."""
    if not os.path.isfile(path):
        raise FileNotFoundError(
            f"{description} not found: {path}"
        )
    if os.path.getsize(path) == 0:
        raise RuntimeError(
            f"{description} is empty: {path}"
        )
    return joblib.load(path)


# ============================================================
# LOAD PRODUCTION EMAIL MODEL
# ============================================================

try:
    print(f"[AI] Loading model: {MODEL_PATH}")
    print(f"[AI] Model exists: {os.path.exists(MODEL_PATH)}")

    if os.path.exists(MODEL_PATH):
        print(f"[AI] Model size: {os.path.getsize(MODEL_PATH)} bytes")

    print(f"[AI] Loading vectorizer: {VECTORIZER_PATH}")
    print(f"[AI] Vectorizer exists: {os.path.exists(VECTORIZER_PATH)}")

    if os.path.exists(VECTORIZER_PATH):
        print(
            f"[AI] Vectorizer size: "
            f"{os.path.getsize(VECTORIZER_PATH)} bytes"
        )

    model = joblib.load(MODEL_PATH)

    print(
        f"[AI] Logistic Regression loaded: "
        f"{type(model).__name__}"
    )

    vectorizer = joblib.load(VECTORIZER_PATH)

    print(
        f"[AI] TF-IDF vectorizer loaded: "
        f"{type(vectorizer).__name__}"
    )

    MODEL_STATUS = "ONLINE"
    MODEL_ERROR = ""

except Exception as error:

    import traceback

    model = None
    vectorizer = None

    MODEL_STATUS = "OFFLINE"

    MODEL_ERROR = (
        f"{type(error).__name__}: {error}"
    )

    print("==============================================")
    print("AI MODEL LOADING FAILED")
    print("==============================================")
    print(MODEL_ERROR)
    traceback.print_exc()
    print("==============================================")

# ============================================================
# SECURITY PATTERNS
# ============================================================

URL_PATTERN = re.compile(
    r"(https?://|www\.|bit\.ly|tinyurl\.com|t\.co/)",
    re.IGNORECASE
)

EMAIL_PATTERN = re.compile(
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
    re.IGNORECASE
)


URGENT_WORDS = [
    "urgent",
    "immediately",
    "verify",
    "verification",
    "suspended",
    "suspend",
    "blocked",
    "warning",
    "alert",
    "expire",
    "expired",
    "deadline",
    "action required",
    "confirm now"
]


FINANCIAL_WORDS = [
    "bank",
    "banking",
    "account",
    "payment",
    "credit card",
    "debit card",
    "wallet",
    "transaction",
    "invoice",
    "refund",
    "money",
    "paypal"
]


CREDENTIAL_WORDS = [
    "password",
    "username",
    "login",
    "log in",
    "sign in",
    "credentials",
    "otp",
    "one time password",
    "pin",
    "security code"
]


PRIZE_WORDS = [
    "winner",
    "won",
    "prize",
    "reward",
    "lottery",
    "gift card",
    "congratulations",
    "claim"
]


# ============================================================
# THREAT INDICATOR ANALYSIS
# ============================================================

def analyze_threat_indicators(text):

    lower_text = text.lower()

    indicators = []
    risk_score = 0

    # URL
    if URL_PATTERN.search(text):

        indicators.append({
            "name": "Suspicious link detected",
            "description":
                "The email contains a URL or shortened-link pattern.",
            "severity": "HIGH"
        })

        risk_score += 2

    # Email address
    if EMAIL_PATTERN.search(text):

        indicators.append({
            "name": "Email address detected",
            "description":
                "The message contains an email address.",
            "severity": "LOW"
        })

    # Urgency
    if any(word in lower_text for word in URGENT_WORDS):

        indicators.append({
            "name": "Urgency language",
            "description":
                "The message attempts to create pressure or immediate action.",
            "severity": "MEDIUM"
        })

        risk_score += 1

    # Financial
    if any(word in lower_text for word in FINANCIAL_WORDS):

        indicators.append({
            "name": "Financial terminology",
            "description":
                "Banking, payment or financial terminology was detected.",
            "severity": "MEDIUM"
        })

        risk_score += 1

    # Credentials
    if any(word in lower_text for word in CREDENTIAL_WORDS):

        indicators.append({
            "name": "Credential-related language",
            "description":
                "Login, password, OTP or credential-related terminology was detected.",
            "severity": "HIGH"
        })

        risk_score += 2

    # Prize
    if any(word in lower_text for word in PRIZE_WORDS):

        indicators.append({
            "name": "Prize/reward language",
            "description":
                "Prize, reward or winner-related terminology was detected.",
            "severity": "MEDIUM"
        })

        risk_score += 1

    # Excessive punctuation
    if text.count("!") >= 3:

        indicators.append({
            "name": "Excessive punctuation",
            "description":
                "Multiple exclamation marks may indicate aggressive or urgent wording.",
            "severity": "LOW"
        })

        risk_score += 1

    # No indicators
    if not indicators:

        indicators.append({
            "name": "No obvious rule-based indicators",
            "description":
                "No common heuristic warning patterns were detected.",
            "severity": "LOW"
        })

    return indicators, min(risk_score, 7)


# ============================================================
# AI PREDICTION
# ============================================================

def predict_email(text):

    if model is None or vectorizer is None:
        raise RuntimeError(
            "AI model or TF-IDF vectorizer could not be loaded. "
            f"MODEL_STATUS={MODEL_STATUS}; "
            f"MODEL_ERROR={MODEL_ERROR}"
        )

    features = vectorizer.transform([text])

    prediction = int(
        model.predict(features)[0]
    )

    confidence = None

    if hasattr(model, "predict_proba"):

        probabilities = model.predict_proba(features)[0]

        confidence = float(
            max(probabilities) * 100
        )

    if prediction == 1:
        label = "PHISHING"
    else:
        label = "LEGITIMATE"

    return label, confidence


# ============================================================
# PREMIUM HTML
# ============================================================

HTML = r"""
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
>

<title>AI Phishing Detection System</title>


<style>

/* ==========================================================
   GLOBAL
========================================================== */

* {
    box-sizing: border-box;
}

:root {

    --background: #050914;

    --panel: rgba(15, 23, 42, 0.78);

    --panel-light: rgba(30, 41, 59, 0.62);

    --border: rgba(148, 163, 184, 0.15);

    --text: #f8fafc;

    --muted: #94a3b8;

    --cyan: #22d3ee;

    --blue: #3b82f6;

    --purple: #8b5cf6;

    --green: #34d399;

    --red: #fb7185;

    --yellow: #fbbf24;
}


body {

    margin: 0;

    min-height: 100vh;

    color: var(--text);

    font-family:
        Inter,
        "Segoe UI",
        Arial,
        sans-serif;

    background:

        radial-gradient(
            circle at 10% 10%,
            rgba(34, 211, 238, 0.12),
            transparent 30%
        ),

        radial-gradient(
            circle at 90% 15%,
            rgba(139, 92, 246, 0.15),
            transparent 32%
        ),

        radial-gradient(
            circle at 50% 100%,
            rgba(59, 130, 246, 0.08),
            transparent 35%
        ),

        var(--background);
}


body::before {

    content: "";

    position: fixed;

    inset: 0;

    pointer-events: none;

    opacity: 0.25;

    background-image:

        linear-gradient(
            rgba(255,255,255,0.025) 1px,
            transparent 1px
        ),

        linear-gradient(
            90deg,
            rgba(255,255,255,0.025) 1px,
            transparent 1px
        );

    background-size: 42px 42px;
}


.container {

    width: 100%;

    max-width: 1180px;

    margin: auto;

    padding: 28px 20px 60px;

    position: relative;
}


/* ==========================================================
   HEADER
========================================================== */

.header {

    display: flex;

    align-items: center;

    justify-content: space-between;

    gap: 20px;
}


.brand {

    display: flex;

    align-items: center;

    gap: 13px;
}


.logo {

    width: 48px;

    height: 48px;

    display: grid;

    place-items: center;

    border-radius: 15px;

    font-size: 23px;

    background:
        linear-gradient(
            135deg,
            var(--purple),
            var(--cyan)
        );

    box-shadow:
        0 15px 35px
        rgba(34, 211, 238, 0.18);
}


.brand-title {

    font-size: 19px;

    font-weight: 800;
}


.brand-subtitle {

    margin-top: 4px;

    font-size: 11px;

    color: var(--muted);
}


.status {

    display: flex;

    align-items: center;

    gap: 8px;

    padding: 9px 14px;

    border:
        1px solid var(--border);

    border-radius: 999px;

    background:
        rgba(15, 23, 42, 0.65);

    font-size: 11px;
}


.status-dot {

    width: 8px;

    height: 8px;

    border-radius: 50%;

    background: var(--green);

    box-shadow:
        0 0 14px var(--green);

    animation:
        pulse 1.8s infinite;
}


@keyframes pulse {

    0%, 100% {
        opacity: 1;
    }

    50% {
        opacity: 0.35;
    }
}


/* ==========================================================
   HERO
========================================================== */

.hero {

    text-align: center;

    max-width: 780px;

    margin: 65px auto 35px;
}


.eyebrow {

    color: var(--cyan);

    font-size: 11px;

    letter-spacing: 2.5px;

    font-weight: 800;

    text-transform: uppercase;
}


.hero h1 {

    margin: 13px 0 15px;

    font-size:
        clamp(36px, 6vw, 64px);

    line-height: 1;

    letter-spacing: -3px;

    background:
        linear-gradient(
            90deg,
            #ffffff,
            #b7efff,
            #c4b5fd
        );

    -webkit-background-clip: text;

    background-clip: text;

    color: transparent;
}


.hero p {

    color: var(--muted);

    line-height: 1.7;

    font-size: 14px;
}


/* ==========================================================
   CARDS
========================================================== */

.card {

    border:
        1px solid var(--border);

    background:
        var(--panel);

    border-radius: 24px;

    backdrop-filter:
        blur(22px);

    box-shadow:
        0 30px 80px
        rgba(0, 0, 0, 0.35);
}


/* ==========================================================
   SCANNER
========================================================== */

.scanner {

    padding: 24px;
}


.label-row {

    display: flex;

    justify-content: space-between;

    margin-bottom: 10px;
}


.label {

    font-size: 13px;

    font-weight: 750;
}


.counter {

    font-size: 10px;

    color: var(--muted);
}


textarea {

    width: 100%;

    min-height: 235px;

    resize: vertical;

    outline: none;

    border:
        1px solid
        rgba(148, 163, 184, 0.18);

    border-radius: 18px;

    background:
        rgba(2, 8, 23, 0.75);

    color: #e2e8f0;

    padding: 18px;

    font:
        14px/1.7
        Consolas,
        monospace;

    transition: 0.25s;
}


textarea:focus {

    border-color:
        rgba(34, 211, 238, 0.55);

    box-shadow:
        0 0 0 4px
        rgba(34, 211, 238, 0.07);
}


/* ==========================================================
   BUTTONS
========================================================== */

.actions {

    display: flex;

    flex-wrap: wrap;

    gap: 10px;

    margin-top: 15px;
}


button {

    border: none;

    border-radius: 13px;

    padding:
        12px 18px;

    color: white;

    font-weight: 750;

    font-size: 12px;

    cursor: pointer;

    transition: 0.2s;
}


button:hover {

    transform:
        translateY(-2px);
}


.primary {

    background:
        linear-gradient(
            135deg,
            var(--purple),
            var(--blue),
            var(--cyan)
        );

    box-shadow:
        0 12px 35px
        rgba(59, 130, 246, 0.2);
}


.secondary {

    background:
        rgba(51, 65, 85, 0.62);

    border:
        1px solid var(--border);
}


.example {

    margin-left: auto;
}


/* ==========================================================
   LOADING
========================================================== */

.loading {

    display: none;

    margin-top: 18px;
}


.loading-text {

    font-size: 11px;

    color: var(--muted);

    margin-bottom: 7px;
}


.loading-bar {

    height: 5px;

    overflow: hidden;

    border-radius: 20px;

    background:
        #172235;
}


.loading-bar span {

    display: block;

    width: 30%;

    height: 100%;

    background:
        linear-gradient(
            90deg,
            var(--purple),
            var(--cyan)
        );

    animation:
        scanning 1s infinite;
}


@keyframes scanning {

    from {
        transform: translateX(-150%);
    }

    to {
        transform: translateX(400%);
    }
}


/* ==========================================================
   RESULT
========================================================== */

.result {

    display: none;

    margin-top: 18px;

    animation:
        appear 0.45s ease;
}


@keyframes appear {

    from {

        opacity: 0;

        transform:
            translateY(12px);
    }

    to {

        opacity: 1;

        transform:
            translateY(0);
    }
}


.result-header {

    display: flex;

    align-items: center;

    justify-content: space-between;

    gap: 20px;

    padding: 22px;

    border-radius: 19px;

    background:
        var(--panel-light);

    border:
        1px solid var(--border);
}


.result-left {

    display: flex;

    align-items: center;

    gap: 15px;
}


.result-icon {

    width: 55px;

    height: 55px;

    display: grid;

    place-items: center;

    border-radius: 17px;

    font-size: 25px;

    color: var(--green);

    background:
        rgba(52, 211, 153, 0.1);
}


.result.phishing .result-icon {

    color: var(--red);

    background:
        rgba(251, 113, 133, 0.1);
}


.result-title {

    font-size: 21px;

    font-weight: 850;
}


.result-description {

    margin-top: 5px;

    font-size: 11px;

    color: var(--muted);
}


.confidence {

    text-align: right;
}


.confidence strong {

    display: block;

    font-size: 28px;
}


.confidence span {

    font-size: 9px;

    color: var(--muted);

    letter-spacing: 1px;
}


/* ==========================================================
   GRID
========================================================== */

.grid {

    display: grid;

    grid-template-columns:
        1.1fr 0.9fr;

    gap: 16px;

    margin-top: 16px;
}


.inner {

    padding: 20px;
}


.inner h3 {

    margin:
        0 0 15px;

    font-size: 13px;
}


/* ==========================================================
   INDICATORS
========================================================== */

.indicator {

    display: flex;

    gap: 11px;

    padding:
        11px 0;

    border-bottom:
        1px solid
        rgba(148, 163, 184, 0.07);
}


.indicator:last-child {

    border-bottom: none;
}


.indicator-dot {

    width: 7px;

    min-width: 7px;

    height: 7px;

    margin-top: 6px;

    border-radius: 50%;

    background: var(--yellow);
}


.indicator-dot.high {

    background:
        var(--red);
}


.indicator-dot.low {

    background:
        var(--green);
}


.indicator-dot.medium {

    background:
        var(--yellow);
}


.indicator-title {

    font-size: 11px;

    font-weight: 750;
}


.indicator-description {

    margin-top: 4px;

    color: var(--muted);

    font-size: 10px;

    line-height: 1.5;
}


/* ==========================================================
   METRICS
========================================================== */

.metrics {

    display: grid;

    grid-template-columns:
        repeat(2, 1fr);

    gap: 10px;
}


.metric {

    padding: 14px;

    border-radius: 14px;

    background:
        rgba(2, 8, 23, 0.42);

    border:
        1px solid var(--border);
}


.metric-label {

    color: var(--muted);

    font-size: 9px;

    margin-bottom: 7px;
}


.metric-value {

    font-size: 14px;

    font-weight: 800;
}


/* ==========================================================
   HISTORY
========================================================== */

.history {

    margin-top: 16px;

    padding: 20px;
}


.history-head {

    display: flex;

    align-items: center;

    justify-content: space-between;
}


.history-title {

    font-size: 13px;

    font-weight: 800;
}


.history-item {

    display: flex;

    align-items: center;

    justify-content: space-between;

    gap: 15px;

    padding:
        12px 0;

    border-bottom:
        1px solid
        rgba(148, 163, 184, 0.07);
}


.history-message {

    overflow: hidden;

    text-overflow: ellipsis;

    white-space: nowrap;

    color: #cbd5e1;

    font-size: 11px;
}


.history-meta {

    display: flex;

    align-items: center;

    gap: 8px;
}


.pill {

    padding:
        5px 8px;

    border-radius: 999px;

    font-size: 8px;

    font-weight: 850;
}


.pill-good {

    color: var(--green);

    background:
        rgba(52, 211, 153, 0.1);
}


.pill-bad {

    color: var(--red);

    background:
        rgba(251, 113, 133, 0.1);
}


.history-time {

    color: var(--muted);

    font-size: 8px;
}


/* ==========================================================
   FOOTER
========================================================== */

.footer {

    text-align: center;

    margin-top: 30px;

    color: #64748b;

    font-size: 9px;
}


/* ==========================================================
   MOBILE
========================================================== */

@media (max-width: 800px) {

    .grid {

        grid-template-columns: 1fr;
    }

    .example {

        margin-left: 0;
    }
}


@media (max-width: 600px) {

    .container {

        padding:
            18px 12px 40px;
    }

    .header {

        align-items:
            flex-start;
    }

    .status {

        font-size: 9px;
    }

    .hero {

        margin-top: 45px;
    }

    .hero h1 {

        font-size: 39px;
    }

    .scanner {

        padding: 15px;
    }

    .result-header {

        flex-direction:
            column;

        align-items:
            flex-start;
    }

    .confidence {

        text-align:
            left;
    }

    .metrics {

        grid-template-columns: 1fr;
    }

}

</style>

</head>


<body>


<div class="container">


<!-- ========================================================
     HEADER
======================================================== -->

<header class="header">

    <div class="brand">

        <div class="logo">
            🛡️
        </div>

        <div>

            <div class="brand-title">
                AI Phishing Detection
            </div>

            <div class="brand-subtitle">
                Intelligent Email Security Platform
            </div>

        </div>

    </div>


    <div class="status">

        <span class="status-dot"></span>

        AI ENGINE {{ status }}

    </div>

</header>


<!-- ========================================================
     HERO
======================================================== -->

<section class="hero">

    <div class="eyebrow">
        AI SECURITY ENGINE
    </div>


    <h1>
        Detect threats<br>
        before they reach you.
    </h1>


    <p>

        Analyze suspicious email content using a trained
        machine-learning model and identify potential
        phishing characteristics within seconds.

    </p>

</section>


<!-- ========================================================
     SCANNER
======================================================== -->

<section class="card scanner">


    <div class="label-row">

        <div class="label">
            Email Content
        </div>

        <div
            class="counter"
            id="counter"
        >
            0 characters
        </div>

    </div>


    <textarea
        id="emailText"
        placeholder="Paste the complete email message here..."
    ></textarea>


    <div class="actions">


        <button
            class="primary"
            onclick="analyzeEmail()"
        >
            🔍 Analyze Email
        </button>


        <button
            class="secondary"
            onclick="clearInput()"
        >
            Clear
        </button>


        <button
            class="secondary example"
            onclick="loadExample()"
        >
            🧪 Load Example
        </button>


    </div>


    <!-- LOADING -->

    <div
        class="loading"
        id="loading"
    >

        <div class="loading-text">
            AI engine is analyzing the email...
        </div>


        <div class="loading-bar">
            <span></span>
        </div>

    </div>


    <!-- ====================================================
         RESULT
    ==================================================== -->

    <div
        class="result"
        id="result"
    >


        <div class="result-header">


            <div class="result-left">


                <div
                    class="result-icon"
                    id="resultIcon"
                >
                    ✓
                </div>


                <div>

                    <div
                        class="result-title"
                        id="resultTitle"
                    >
                        LEGITIMATE
                    </div>


                    <div
                        class="result-description"
                        id="resultDescription"
                    >
                        Analysis completed.
                    </div>

                </div>

            </div>


            <div class="confidence">

                <strong id="confidence">
                    --
                </strong>

                <span>
                    MODEL CONFIDENCE
                </span>

            </div>


        </div>


        <!-- RESULT GRID -->

        <div class="grid">


            <!-- THREAT INDICATORS -->

            <div class="card inner">

                <h3>
                    🔎 Threat Indicators
                </h3>

                <div id="indicators"></div>

            </div>


            <!-- ANALYSIS -->

            <div class="card inner">

                <h3>
                    📊 Analysis Summary
                </h3>


                <div class="metrics">


                    <div class="metric">

                        <div class="metric-label">
                            CLASSIFICATION
                        </div>

                        <div
                            class="metric-value"
                            id="metricClass"
                        >
                            --
                        </div>

                    </div>


                    <div class="metric">

                        <div class="metric-label">
                            AI MODEL
                        </div>

                        <div class="metric-value">
                            Logistic Regression
                        </div>

                    </div>


                    <div class="metric">

                        <div class="metric-label">
                            FEATURES
                        </div>

                        <div class="metric-value">
                            TF-IDF
                        </div>

                    </div>


                    <div class="metric">

                        <div class="metric-label">
                            ENGINE STATUS
                        </div>

                        <div class="metric-value">
                            {{ status }}
                        </div>

                    </div>


                </div>

            </div>


        </div>

    </div>


</section>


<!-- ========================================================
     HISTORY
======================================================== -->

<section class="card history">


    <div class="history-head">

        <div class="history-title">
            🕘 Recent Scans
        </div>


        <button
            class="secondary"
            onclick="clearHistory()"
            style="
                padding:7px 10px;
                font-size:9px;
            "
        >
            Clear History
        </button>

    </div>


    <div
        id="historyList"
        style="margin-top:10px;"
    ></div>


</section>


<!-- ========================================================
     FOOTER
======================================================== -->

<div class="footer">

    AI Phishing Detection System
    •
    Machine Learning Research Prototype
    •
    Human verification is recommended for security decisions.

</div>


</div>


<script>


// ========================================================
// ELEMENTS
// ========================================================

const emailText =
    document.getElementById("emailText");

const counter =
    document.getElementById("counter");


// ========================================================
// CHARACTER COUNTER
// ========================================================

emailText.addEventListener(
    "input",
    function () {

        counter.textContent =
            emailText.value.length.toLocaleString()
            + " characters";

    }
);


// ========================================================
// HTML ESCAPE
// ========================================================

function escapeHTML(value) {

    return String(value).replace(
        /[&<>"']/g,
        function (character) {

            const entities = {

                "&": "&amp;",
                "<": "&lt;",
                ">": "&gt;",
                '"': "&quot;",
                "'": "&#039;"

            };

            return entities[character];

        }
    );

}


// ========================================================
// LOAD EXAMPLE
// ========================================================

function loadExample() {

    emailText.value =
`URGENT: Your bank account has been temporarily suspended.

You must verify your account immediately to avoid permanent closure.

Click the link below and enter your username, password, OTP and security code to restore access.

Congratulations! You may also be eligible for a special reward.`;

    emailText.dispatchEvent(
        new Event("input")
    );

}


// ========================================================
// ANALYZE EMAIL
// ========================================================

async function analyzeEmail() {

    const text =
        emailText.value.trim();


    if (!text) {

        alert(
            "Please enter an email message first."
        );

        emailText.focus();

        return;

    }


    const loading =
        document.getElementById("loading");

    const result =
        document.getElementById("result");


    loading.style.display =
        "block";

    result.style.display =
        "none";


    try {

        const response =
            await fetch(
                "/api/analyze",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        text: text
                    })
                }
            );


        const data =
            await response.json();


        if (!response.ok) {

            throw new Error(
                data.error ||
                "Analysis failed."
            );

        }


        setTimeout(
            function () {

                showResult(data);

            },
            600
        );


    } catch (error) {

        loading.style.display =
            "none";

        alert(
            error.message
        );

    }

}


// ========================================================
// SHOW RESULT
// ========================================================

function showResult(data) {

    document.getElementById(
        "loading"
    ).style.display = "none";


    const result =
        document.getElementById(
            "result"
        );


    result.style.display =
        "block";


    const isPhishing =
        data.label === "PHISHING";


    result.classList.toggle(
        "phishing",
        isPhishing
    );


    document.getElementById(
        "resultIcon"
    ).textContent =
        isPhishing ? "!" : "✓";


    document.getElementById(
        "resultTitle"
    ).textContent =
        data.label;


    document.getElementById(
        "resultDescription"
    ).textContent =

        isPhishing

        ?

        "Potential phishing characteristics detected. Review this message carefully."

        :

        "The AI model classified this message as legitimate.";


    document.getElementById(
        "confidence"
    ).textContent =

        data.confidence === null ||
        data.confidence === undefined

        ?

        "N/A"

        :

        Number(data.confidence).toFixed(2)
        + "%";


    document.getElementById(
        "metricClass"
    ).textContent =
        data.label;


    // ----------------------------------------------------
    // INDICATORS
    // ----------------------------------------------------

    const indicatorContainer =
        document.getElementById(
            "indicators"
        );


    indicatorContainer.innerHTML =
        data.indicators.map(
            function (item) {

                const severity =
                    String(
                        item.severity || "LOW"
                    ).toLowerCase();


                return `

                    <div class="indicator">

                        <span
                            class="indicator-dot ${severity}"
                        ></span>

                        <div>

                            <div class="indicator-title">
                                ${escapeHTML(item.name)}
                            </div>

                            <div class="indicator-description">
                                ${escapeHTML(item.description)}
                            </div>

                        </div>

                    </div>

                `;

            }
        ).join("");


    saveHistory(data);


    result.scrollIntoView({
        behavior: "smooth",
        block: "nearest"
    });

}


// ========================================================
// SAVE HISTORY
// ========================================================

function saveHistory(data) {

    let history = [];

    try {

        history =
            JSON.parse(
                localStorage.getItem(
                    "phishingHistory"
                ) || "[]"
            );

        if (!Array.isArray(history)) {
            history = [];
        }

    } catch (error) {

        history = [];

    }


    history.unshift({

        message:
            emailText.value.trim(),

        label:
            data.label,

        confidence:
            data.confidence,

        time:
            new Date().toLocaleString()

    });


    history =
        history.slice(0, 10);


    localStorage.setItem(
        "phishingHistory",
        JSON.stringify(history)
    );


    renderHistory();

}


// ========================================================
// RENDER HISTORY
// ========================================================

function renderHistory() {

    const list =
        document.getElementById(
            "historyList"
        );


    let history = [];

    try {

        history =
            JSON.parse(
                localStorage.getItem(
                    "phishingHistory"
                ) || "[]"
            );

        if (!Array.isArray(history)) {
            history = [];
        }

    } catch (error) {

        history = [];

    }


    if (history.length === 0) {

        list.innerHTML = `

            <div
                style="
                    color:#64748b;
                    font-size:10px;
                    padding:14px 0;
                "
            >

                No scans yet.
                Your recent AI analyses
                will appear here.

            </div>

        `;

        return;

    }


    list.innerHTML =
        history.map(
            function (item) {

                const phishing =
                    item.label === "PHISHING";


                return `

                    <div class="history-item">

                        <div class="history-message">
                            ${escapeHTML(
                                item.message
                            )}
                        </div>


                        <div class="history-meta">

                            <span
                                class="
                                    pill
                                    ${
                                        phishing
                                        ?
                                        "pill-bad"
                                        :
                                        "pill-good"
                                    }
                                "
                            >
                                ${escapeHTML(
                                    item.label
                                )}
                            </span>


                            <span class="history-time">
                                ${escapeHTML(
                                    item.time
                                )}
                            </span>

                        </div>

                    </div>

                `;

            }
        ).join("");

}


// ========================================================
// CLEAR HISTORY
// ========================================================

function clearHistory() {

    localStorage.removeItem(
        "phishingHistory"
    );

    renderHistory();

}


// ========================================================
// CLEAR INPUT
// ========================================================

function clearInput() {

    emailText.value = "";

    emailText.dispatchEvent(
        new Event("input")
    );


    document.getElementById(
        "result"
    ).style.display = "none";


    document.getElementById(
        "loading"
    ).style.display = "none";


    emailText.focus();

}


// ========================================================
// START
// ========================================================

renderHistory();

</script>


</body>

</html>
"""


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    return render_template_string(
        HTML,
        status=MODEL_STATUS
    )


# ============================================================
# SYSTEM STATUS
# ============================================================

@app.route("/api/status")
def system_status():

    return jsonify({

        "status": MODEL_STATUS,

        "model":
            os.path.basename(MODEL_PATH),

        "vectorizer":
            os.path.basename(VECTORIZER_PATH),

        "error":
            MODEL_ERROR,

        "url_model_status":
            URL_MODEL_STATUS,

        "url_model":
            os.path.basename(URL_MODEL_PATH),

        "url_analyzer":
            "ONLINE" if analyze_text_urls is not None else "OFFLINE",

        "url_error":
            URL_MODEL_ERROR or URL_ANALYZER_IMPORT_ERROR

    })


# ============================================================
# ANALYZE API
# ============================================================
@app.route("/api/debug-model", methods=["GET"])
def debug_model():
    return jsonify({
        "status": "DEBUG_ROUTE_WORKING",
        "deployment_version": DEPLOYMENT_VERSION,
        "model_status": MODEL_STATUS,
        "model_error": MODEL_ERROR,
        "base_dir": BASE_DIR,
        "model_path": MODEL_PATH,
        "vectorizer_path": VECTORIZER_PATH,
        "model_exists": os.path.isfile(MODEL_PATH),
        "vectorizer_exists": os.path.isfile(VECTORIZER_PATH),
        "model_size": (
            os.path.getsize(MODEL_PATH)
            if os.path.isfile(MODEL_PATH)
            else 0
        ),
        "vectorizer_size": (
            os.path.getsize(VECTORIZER_PATH)
            if os.path.isfile(VECTORIZER_PATH)
            else 0
        ),
        "model_loaded": model is not None,
        "vectorizer_loaded": vectorizer is not None
    })

@app.route(
    "/api/analyze",
    methods=["POST"]
)
def analyze():

    try:

        data = request.get_json(
            silent=True
        ) or {}


        text = str(
            data.get(
                "text",
                ""
            )
        ).strip()


        if not text:

            return jsonify({
                "error":
                    "Email text is empty."
            }), 400


        if len(text) > 100000:

            return jsonify({
                "error":
                    "Email is too large. Maximum 100,000 characters."
            }), 400


        # AI prediction

        label, confidence = \
            predict_email(text)


        # Threat indicators

        indicators, risk_score = \
            analyze_threat_indicators(
                text
            )

        # Live URL analysis. The email classifier remains usable even if
        # the optional URL component is unavailable.
        url_analysis = {
            "urls": [],
            "highest_risk": "NONE",
            "highest_score": 0,
            "total_urls": 0
        }

        if analyze_text_urls is not None:
            try:
                url_analysis = analyze_text_urls(text)
            except Exception as url_error:
                url_analysis = {
                    "urls": [],
                    "highest_risk": "ERROR",
                    "highest_score": 0,
                    "total_urls": 0,
                    "error": f"{type(url_error).__name__}: {url_error}"
                }

        return jsonify({

            "label":
                label,

            "confidence":
                confidence,

            "indicators":
                indicators,

            "risk_score":
                risk_score,

            "url_analysis":
                url_analysis,

            "character_count":
                len(text),

            "timestamp":
                datetime.now().isoformat(
                    timespec="seconds"
                )

        })


    except Exception as error:

        return jsonify({

            "error":
                "Analysis error: " +
                str(error)

        }), 500


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 60)
    print(" AI PHISHING DETECTION SYSTEM")
    print(" PREMIUM ULTRA WEB APPLICATION")
    print("=" * 60)

    print(
        "MODEL      :",
        os.path.basename(MODEL_PATH)
    )

    print(
        "VECTORIZER :",
        os.path.basename(VECTORIZER_PATH)
    )

    print(
        "STATUS     :",
        MODEL_STATUS
    )

    if MODEL_ERROR:

        print(
            "ERROR      :",
            MODEL_ERROR
        )

    print("=" * 60)

    print(
        "LOCAL URL  : http://127.0.0.1:5000"
    )

    print(
        "NETWORK URL: http://YOUR-PC-IP:5000"
    )

    print("=" * 60)
    print()


    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )