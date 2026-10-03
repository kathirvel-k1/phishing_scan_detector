"""Explainable, offline message and URL risk analysis.

The scorer deliberately reports evidence rather than pretending to prove intent.
It can be replaced or augmented with a trained model behind the same interface.
"""

from __future__ import annotations

import re
import logging
from urllib.parse import urlparse

from app.ai_agent import analyze_with_openai, is_openai_configured
from app.schemas import AnalyzeResponse, CheckedUrl, WarningSign
from app.text_model import MODEL


MAX_URLS = 12
logger = logging.getLogger(__name__)

URL_PATTERN = re.compile(
    r"(?i)\b(?:(?:https?://|www\.)?(?:\d{1,3}(?:\.\d{1,3}){3}|"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})))"
    r"(?::\d{2,5})?"
    r"(?:/[^\s<>\"']*)?(?:\?[^\s<>\"']*)?(?:#[^\s<>\"']*)?"
)

SIGNAL_GROUPS: list[tuple[str, str, int, str, str]] = [
    (
        "credential_request",
        r"\b(?:confirm|verify|validate|reset|update|unlock|restore)\b.{0,45}\b(?:password|passcode|login|account|identity|credentials?)\b|\b(?:password|passcode|otp|one[- ]time code|security code)\b.{0,35}\b(?:send|share|reply|provide|enter|confirm)\b",
        27,
        "Requests for sensitive information",
        "The message asks you to enter, confirm, or share account credentials or a security code. Legitimate support teams should not ask you to send a one-time code in a message.",
    ),
    (
        "threat_or_urgency",
        r"\b(?:immediately|urgent(?:ly)?|act now|final notice|within\s+\d+\s+hours?|expires? today|suspended|will be closed|limited time|avoid (?:a )?fee|legal action)\b",
        18,
        "Pressure to act quickly",
        "Urgent deadlines or threats can be used to make you act before checking the request independently.",
    ),
    (
        "payment_request",
        r"\b(?:gift cards?|wire transfer|bitcoin|cryptocurrency|crypto wallet|pay a (?:small )?fee|processing fee|payment required|send money|bank transfer)\b",
        23,
        "Unusual payment request",
        "The message mentions a payment method or fee often used to make scam payments difficult to reverse.",
    ),
    (
        "prize_bait",
        r"\b(?:you(?:'|’)ve|you have)\s+won\b|\bclaim your (?:prize|reward|gift|refund)\b|\bfree (?:gift|voucher|iphone|prize)\b|\bselected as (?:a )?(?:winner|recipient)\b",
        16,
        "Unexpected prize or reward",
        "An unexpected prize or refund can be bait to collect personal details or a payment.",
    ),
    (
        "identity_impersonation",
        r"\b(?:bank|paypal|microsoft|apple|amazon|netflix|irs|tax office|delivery company|support team)\b.{0,60}\b(?:verify|suspended|locked|failed|problem|refund|security alert)\b|\b(?:security alert|account problem|delivery failed|payment failed)\b",
        14,
        "Possible organization impersonation",
        "The message uses a familiar service or authority together with an account or payment problem. Verify it through the official app or website.",
    ),
]

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly", "buff.ly"}
RISKY_TLDS = {"click", "top", "xyz", "icu", "cam", "zip", "mov", "tk", "work", "gq"}
KNOWN_BRANDS = {
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.in"},
    "apple": {"apple.com", "icloud.com"},
    "google": {"google.com", "google.co.in", "accounts.google.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com"},
    "paypal": {"paypal.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com"},
    "dhl": {"dhl.com"},
}


def _clean_url(value: str) -> str:
    return value.rstrip(".,!?;:)]}>")


def _extract_urls(message: str) -> list[str]:
    urls: list[str] = []
    for match in URL_PATTERN.finditer(message):
        candidate = _clean_url(match.group(0))
        if candidate and candidate not in urls:
            urls.append(candidate)
        if len(urls) >= MAX_URLS:
            break
    return urls


def _host_for(url: str) -> tuple[str, str]:
    normalized = url if "://" in url else f"https://{url}"
    parsed = urlparse(normalized)
    return normalized, (parsed.hostname or "").lower().rstrip(".")


def _analyze_url(url: str) -> CheckedUrl:
    normalized, host = _host_for(url)
    parsed = urlparse(normalized)
    indicators: list[str] = []
    score = 0

    if parsed.scheme != "https":
        indicators.append("The link does not use a secure HTTPS connection.")
        score += 8
    if host in SHORTENERS:
        indicators.append("A link shortener hides the final destination.")
        score += 16
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        indicators.append("The link points to a raw IP address instead of a recognizable domain.")
        score += 25
    if "xn--" in host:
        indicators.append("The domain uses encoded characters that can resemble other letters.")
        score += 24
    labels = host.split(".") if host else []
    if len(labels) >= 5:
        indicators.append("The domain has an unusually long chain of subdomains.")
        score += 10
    if "@" in parsed.netloc:
        indicators.append("The link contains an @ sign that can disguise its real destination.")
        score += 20
    try:
        port = parsed.port
    except ValueError:
        port = None
        indicators.append("The link contains a malformed network port.")
        score += 12
    if port and port not in {80, 443}:
        indicators.append("The link uses a nonstandard network port.")
        score += 8

    for brand, official_domains in KNOWN_BRANDS.items():
        if brand in host and host not in official_domains and not any(host.endswith("." + d) for d in official_domains):
            indicators.append(f"The domain mentions {brand.title()} but is not one of its recognized domains.")
            score += 25
            break

    tld = labels[-1] if labels else ""
    if tld in RISKY_TLDS:
        indicators.append(f"The .{tld} domain ending is commonly associated with higher-risk links.")
        score += 12
    if re.search(r"\b(?:login|verify|secure|account|billing|password|signin)\b", host):
        indicators.append("The domain name uses account or sign-in wording.")
        score += 10

    return CheckedUrl(url=url, domain=host or "Unknown domain", risk=min(score, 100), indicators=indicators)


def analyze_message(message: str) -> AnalyzeResponse:
    text = message.strip()
    lower = text.lower()
    signs: list[WarningSign] = []
    text_score = 0

    for key, pattern, points, title, detail in SIGNAL_GROUPS:
        if re.search(pattern, lower, re.IGNORECASE):
            text_score += points
            signs.append(WarningSign(title=title, detail=detail, severity="high" if points >= 23 else "medium"))

    model_probability = MODEL.scam_probability(text)
    # Allow the small text model to add context without letting its demo corpus
    # dominate the more specific, directly explainable warning signals.
    if model_probability >= 0.94 and not any(sign.title == "Possible scam-like wording" for sign in signs):
        signs.append(
            WarningSign(
                title="Wording resembles common scam examples",
                detail="A small local Naive Bayes model found similar language in its built-in scam examples. The model has limited training data, so use this as one clue rather than a verdict.",
                severity="medium",
            )
        )

    urls = [_analyze_url(url) for url in _extract_urls(text)]
    strongest_url_risk = max((url.risk for url in urls), default=0)
    if urls:
        url_flags = [(url, indicator) for url in urls for indicator in url.indicators]
        if url_flags:
            # Group URL findings into one clear warning while preserving each URL below.
            domains = ", ".join(dict.fromkeys(url.domain for url, _ in url_flags))
            signs.append(
                WarningSign(
                    title="Link needs careful verification",
                    detail=f"At least one link has characteristics worth checking ({domains}). Open the official site directly instead of using the message link.",
                    severity="high" if strongest_url_risk >= 35 else "medium",
                )
            )
        elif all(urlparse(_host_for(url.url)[0]).scheme == "https" for url in urls):
            # HTTPS is useful context, but it does not establish that a site is trustworthy.
            pass

    ml_context = round((model_probability - 0.78) * 42) if model_probability >= 0.78 else 0
    score = min(100, text_score + round(strongest_url_risk * 0.8) + min(9, ml_context))
    if score >= 60:
        classification = "High risk"
        summary = "This message has several strong scam signals. Avoid its links and verify the request through a trusted channel."
    elif score >= 30:
        classification = "Use caution"
        summary = "Some details deserve a closer look. Verify the sender and request independently before taking action."
    else:
        classification = "Lower risk"
        summary = "We found few common scam signals. This is not proof that the sender or links are safe."

    if not signs:
        signs.append(
            WarningSign(
                title="No strong warning signs found",
                detail="The message did not match the common pressure, credential, payment, or suspicious-link patterns checked by this demo.",
                severity="info",
            )
        )

    recommendations = [
        "Do not share passwords, one-time codes, or payment details in response to a message.",
        "If it claims to be from a company, open its official app or type its known website address yourself.",
    ]
    if score >= 30:
        recommendations.insert(0, "Pause before replying, paying, or opening any link in the message.")

    return AnalyzeResponse(
        risk_score=score,
        classification=classification,
        summary=summary,
        warning_signs=signs,
        checked_urls=urls,
        recommendations=recommendations,
        analysis_mode="Local Naive Bayes + explainable signals",
    )


async def analyze_message_with_agent(message: str) -> AnalyzeResponse:
    """Use OpenAI when configured; preserve a working local fallback."""
    local_result = analyze_message(message)
    if not is_openai_configured():
        return local_result.model_copy(
            update={"analysis_mode": "Demo AI agent (local NLP + URL checks)"}
        )

    try:
        ai_result, model = await analyze_with_openai(message)
    except Exception as error:
        # Keep the demo usable during key, network, quota, or provider failures.
        # Avoid logging message contents or SDK exception details.
        logger.warning("OpenAI analysis failed; returning local analysis (%s)", type(error).__name__)
        return local_result.model_copy(
            update={"analysis_mode": "Demo AI agent fallback (OpenAI API unavailable)"}
        )

    score = max(local_result.risk_score, ai_result.risk_score)
    if score >= 60:
        classification = "High risk"
    elif score >= 30:
        classification = "Use caution"
    else:
        classification = "Lower risk"

    # If the deterministic local checks raise the score, use their matching
    # summary; otherwise keep the model's context-aware explanation.
    summary = ai_result.summary if ai_result.risk_score >= local_result.risk_score else local_result.summary

    warning_signs: list[WarningSign] = []
    seen_titles: set[str] = set()
    for sign in [*ai_result.warning_signs, *local_result.warning_signs]:
        if sign.title == "No strong warning signs found":
            continue
        key = sign.title.casefold()
        if key in seen_titles:
            continue
        seen_titles.add(key)
        warning_signs.append(
            WarningSign(title=sign.title, detail=sign.detail, severity=sign.severity)
        )
    if not warning_signs:
        warning_signs.append(
            WarningSign(
                title="No strong warning signs found",
                detail="The AI and local checks found few common scam indicators. This does not prove the sender or links are safe.",
                severity="info",
            )
        )

    recommendations = list(dict.fromkeys([*ai_result.recommendations, *local_result.recommendations]))[:5]
    return AnalyzeResponse(
        risk_score=score,
        classification=classification,
        summary=summary,
        warning_signs=warning_signs[:8],
        checked_urls=local_result.checked_urls,
        recommendations=recommendations,
        analysis_mode=f"OpenAI Responses API ({model}) + local URL checks",
    )
