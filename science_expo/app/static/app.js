const messageInput = document.querySelector("#message-input");
const charCount = document.querySelector("#char-count");
const analyzeButton = document.querySelector("#analyze-button");
const clearButton = document.querySelector("#clear-button");
const formError = document.querySelector("#form-error");
const reportContent = document.querySelector("#report-content");
const apiOrigin = window.location.port === "8000" ? "" : "http://127.0.0.1:8000";
const analyzeEndpoint = `${apiOrigin}/api/analyze`;
const healthEndpoint = `${apiOrigin}/api/health`;

const icon = (name) => {
  const paths = {
    warning: '<path d="M12 3.8 22 21H2L12 3.8Z"/><path d="M12 9v5m0 3h.01"/>',
    link: '<path d="M10 13a5 5 0 0 0 7.1 0l2.1-2.1a5 5 0 0 0-7.1-7.1L11 4.9"/><path d="M14 11a5 5 0 0 0-7.1 0l-2.1 2.1a5 5 0 0 0 7.1 7.1l1.1-1.1"/>',
    check: '<path d="m5 12 4.5 4.5L19 7"/>',
    arrow: '<path d="M7 17 17 7M7 7h10v10"/>',
    copy: '<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/>',
  };
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.8");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  svg.innerHTML = paths[name] || paths.warning;
  return svg;
};

function setInputState() {
  charCount.textContent = `${messageInput.value.length.toLocaleString()} / 12,000`;
  analyzeButton.disabled = !messageInput.value.trim() || analyzeButton.dataset.busy === "true";
  formError.hidden = true;
}

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function renderReport(data) {
  const riskClass = data.risk_score >= 60 ? "high" : data.risk_score >= 30 ? "medium" : "low";
  const root = node("div", `result-view risk-${riskClass} result-enter`);
  const summary = node("div", "result-summary");
  const scoreDial = node("div", "score-dial");
  scoreDial.style.setProperty("--score", `${data.risk_score}%`);
  const dialInner = node("div", "score-dial-inner");
  dialInner.append(node("strong", "score-number", String(data.risk_score)));
  dialInner.append(node("span", "score-denominator", "out of 100"));
  scoreDial.append(dialInner);
  const verdict = node("div", "verdict-copy");
  const badge = node("span", "risk-badge");
  const badgeDot = node("i", "");
  badge.append(badgeDot, document.createTextNode(data.classification));
  verdict.append(badge, node("h3", "", "Risk overview"), node("p", "", data.summary));
  summary.append(scoreDial, verdict);
  root.append(summary);

  const signalHeading = node("div", "subsection-heading");
  signalHeading.append(node("h4", "", "What we noticed"), node("span", "finding-count", `${data.warning_signs.length} ${data.warning_signs.length === 1 ? "finding" : "findings"}`));
  root.append(signalHeading);
  const findings = node("div", "finding-list");
  data.warning_signs.forEach((sign) => {
    const item = node("article", `finding-item severity-${sign.severity}`);
    const signIcon = node("span", "finding-icon");
    signIcon.append(icon(sign.severity === "info" ? "check" : "warning"));
    const copy = node("div", "finding-copy");
    copy.append(node("h5", "", sign.title), node("p", "", sign.detail));
    item.append(signIcon, copy);
    findings.append(item);
  });
  root.append(findings);

  if (data.checked_urls.length) {
    const urlTitle = node("div", "subsection-heading url-heading");
    urlTitle.append(node("h4", "", "Links in this message"), node("span", "finding-count", `${data.checked_urls.length} checked`));
    root.append(urlTitle);
    const urlList = node("div", "url-list");
    data.checked_urls.forEach((url) => {
      const item = node("details", `url-item ${url.risk >= 35 ? "url-risky" : ""}`);
      const summaryEl = node("summary", "url-summary");
      const linkIcon = node("span", "url-icon");
      linkIcon.append(icon("link"));
      const host = node("span", "url-host", url.domain);
      const riskTag = node("span", "url-risk", url.risk ? `${url.risk} signals` : "No flags");
      summaryEl.append(linkIcon, host, riskTag);
      const body = node("div", "url-details");
      body.append(node("p", "url-full", url.url));
      if (url.indicators.length) {
        const ul = node("ul", "url-indicators");
        url.indicators.forEach((indicator) => ul.append(node("li", "", indicator)));
        body.append(ul);
      } else {
        body.append(node("p", "url-clear", "No common URL warning signs were found. This does not confirm the site is safe."));
      }
      item.append(summaryEl, body);
      urlList.append(item);
    });
    root.append(urlList);
  }

  const nextSteps = node("div", "next-steps");
  nextSteps.append(node("h4", "", "Safer next steps"));
  const recommendations = node("ul", "recommendation-list");
  data.recommendations.forEach((recommendation) => {
    const li = node("li", "");
    const check = node("span", "recommendation-check", "✓");
    li.append(check, node("span", "", recommendation));
    recommendations.append(li);
  });
  nextSteps.append(recommendations);
  root.append(nextSteps);

  const footer = node("div", "report-footer");
  const mode = node("span", "analysis-mode", data.analysis_mode);
  const copyButton = node("button", "copy-button", "Copy summary");
  copyButton.type = "button";
  copyButton.prepend(icon("copy"));
  copyButton.addEventListener("click", async () => {
    const plainText = [
      `PhishGuard result: ${data.classification} (${data.risk_score}/100)`,
      data.summary,
      "Warning signs:",
      ...data.warning_signs.map((sign) => `• ${sign.title}: ${sign.detail}`),
    ].join("\n");
    try {
      await navigator.clipboard.writeText(plainText);
      copyButton.lastChild.textContent = "Copied";
      window.setTimeout(() => { copyButton.lastChild.textContent = "Copy summary"; }, 1600);
    } catch {
      copyButton.lastChild.textContent = "Clipboard unavailable";
    }
  });
  footer.append(mode, copyButton);
  root.append(footer);
  reportContent.replaceChildren(root);
  document.querySelector("#report-card").scrollIntoView({ behavior: "smooth", block: "nearest" });
}

async function analyze() {
  const message = messageInput.value.trim();
  if (!message) return;
  formError.hidden = true;
  analyzeButton.dataset.busy = "true";
  analyzeButton.disabled = true;
  analyzeButton.querySelector(".button-label").textContent = "Checking signals";
  analyzeButton.querySelector(".button-arrow").classList.add("button-loading");
  const loading = node("div", "loading-report");
  loading.innerHTML = '<span class="loader-ring" aria-hidden="true"></span><h3>Reading the signs</h3><p>Checking message patterns and visible link details…</p>';
  reportContent.replaceChildren(loading);
  try {
    await updateAgentStatus();
    const response = await fetch(analyzeEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message }),
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.detail || "The analysis could not be completed. Please try again.");
    renderReport(payload);
  } catch (error) {
    const err = node("div", "report-error");
    const isConnectionError = error instanceof TypeError;
    const errorMessage = isConnectionError
      ? "The local analysis server is not reachable. Start it with: uvicorn app.main:app --reload"
      : (error.message || "Check your connection and try again.");
    err.append(node("h3", "", "We couldn’t analyze that message"), node("p", "", errorMessage));
    reportContent.replaceChildren(err);
    formError.textContent = errorMessage;
    formError.hidden = false;
  } finally {
    analyzeButton.dataset.busy = "false";
    analyzeButton.disabled = !messageInput.value.trim();
    analyzeButton.querySelector(".button-label").textContent = "Analyze message";
    analyzeButton.querySelector(".button-arrow").classList.remove("button-loading");
  }
}

async function updateAgentStatus() {
  const status = document.querySelector(".header-status");
  if (!status) return;
  const label = status.querySelector("span:last-child");
  const privacyChip = document.querySelector("#privacy-chip-label");
  const privacyNote = document.querySelector("#privacy-note-text");
  try {
    const response = await fetch(healthEndpoint, { signal: AbortSignal.timeout(2500) });
    if (!response.ok) throw new Error("Analyzer unavailable");
    const health = await response.json();
    const usingOpenAI = health.provider === "openai";
    label.textContent = usingOpenAI ? "OpenAI agent ready" : "Demo AI agent ready";
    if (privacyChip) privacyChip.textContent = usingOpenAI ? "OpenAI AI analysis" : "Demo AI mode";
    if (privacyNote) privacyNote.textContent = usingOpenAI
      ? "Message text is sent to OpenAI for analysis"
      : "Demo agent analyzes locally; this app does not save your text";
    status.classList.remove("status-offline");
  } catch {
    label.textContent = "Start local analyzer";
    if (privacyChip) privacyChip.textContent = "Analysis server unavailable";
    if (privacyNote) privacyNote.textContent = "Start the backend before analyzing a message";
    status.classList.add("status-offline");
  }
}

messageInput.addEventListener("input", setInputState);
analyzeButton.addEventListener("click", analyze);
clearButton.addEventListener("click", () => {
  messageInput.value = "";
  setInputState();
  messageInput.focus();
});
messageInput.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") analyze();
});
document.querySelectorAll("[data-sample]").forEach((button) => {
  button.addEventListener("click", () => {
    messageInput.value = button.dataset.sample;
    setInputState();
    messageInput.focus();
    document.querySelector("#checker").scrollIntoView({ behavior: "smooth", block: "start" });
  });
});
setInputState();
updateAgentStatus();
