const chatLog = document.querySelector("#chat-log");
const chatForm = document.querySelector("#chat-form");
const chatInput = document.querySelector("#chat-input");
const chatCount = document.querySelector("#chat-count");
const sendButton = document.querySelector("#send-button");
const clearChatButton = document.querySelector("#clear-chat");
const apiOrigin = window.location.port === "8000" ? "" : "http://127.0.0.1:8000";
const analyzeEndpoint = `${apiOrigin}/api/demo/analyze`;
let busy = false;

const samples = {
  account: `Subject: Immediate action required: verify account access

Dear Customer,

Our security team noticed an unusual sign-in attempt on your account. To avoid a temporary interruption, verify your password and confirm your one-time security code within two hours:
http://account-security.example.com/verify

Regards,
Account Security Team`,
  code: `Subject: Congratulations — gift card winner

Hello Jordan,

Your email was selected to receive a $500 gift card. Claim your prize within 24 hours by replying with your one-time security code so we can confirm your identity.

Thank you,
Rewards Team`,
  delivery: `Subject: Delivery reschedule notice

Dear Customer,

We could not complete your parcel delivery today. A small processing fee is required to schedule another attempt. Review the delivery notice here:
http://delivery-status.example.com/parcel

Regards,
Delivery Support`,
  lookalike: `Subject: Shared meeting notes

Hi,

The notes from our meeting are ready. Open the shared file here:
http://xn--paypa1-verify.example/secure

Please let me know if you have trouble viewing it.

Thanks,
Project Team`,
  meeting: `Subject: Project check-in moved to Thursday

Hi Maya,

Our weekly project check-in has moved to Thursday at 10:30 a.m. Please review the meeting notes beforehand and reply if that time no longer works for you.

Thanks,
Sam`,
};

function element(tag, className, text) {
  const result = document.createElement(tag);
  if (className) result.className = className;
  if (text !== undefined) result.textContent = text;
  return result;
}

function updateComposer() {
  chatCount.textContent = `${chatInput.value.length.toLocaleString()} / 12,000`;
  sendButton.disabled = busy || !chatInput.value.trim();
}

function scrollChat() {
  chatLog.scrollTop = chatLog.scrollHeight;
}

function addUserMessage(text) {
  const row = element("article", "chat-row user-row");
  const bubble = element("div", "user-bubble", text);
  row.append(bubble);
  chatLog.append(row);
  scrollChat();
}

function addAgentShell() {
  const row = element("article", "chat-row agent-row response-row");
  const avatar = element("div", "message-avatar", "P");
  avatar.setAttribute("aria-hidden", "true");
  const stack = element("div", "message-stack");
  const byline = element("div", "message-byline");
  byline.append(document.createTextNode("PhishGuard "));
  byline.append(element("span", "", "DEMO AGENT"));
  const bubble = element("div", "agent-bubble response-bubble");
  stack.append(byline, bubble);
  row.append(avatar, stack);
  chatLog.append(row);
  return bubble;
}

function addThinking() {
  const row = element("article", "chat-row agent-row thinking-row");
  const avatar = element("div", "message-avatar", "P");
  avatar.setAttribute("aria-hidden", "true");
  const bubble = element("div", "thinking-bubble");
  bubble.setAttribute("aria-label", "Demo agent is analyzing");
  bubble.append(element("span", "thinking-dot"), element("span", "thinking-dot"), element("span", "thinking-dot"));
  row.append(avatar, bubble);
  chatLog.append(row);
  scrollChat();
  return row;
}

function renderAnalysis(bubble, data) {
  const riskClass = data.risk_score >= 60 ? "high" : data.risk_score >= 30 ? "medium" : "low";
  const verdict = element("div", `agent-verdict verdict-${riskClass}`);
  const score = element("div", "agent-score", `${data.risk_score}<small>/100</small>`);
  const classification = element("span", "agent-classification", data.classification);
  verdict.append(score, classification);
  bubble.append(verdict, element("p", "agent-summary", data.summary));

  const findingsHeading = element("h3", "agent-section-title", "What stood out");
  bubble.append(findingsHeading);
  const findings = element("ul", "agent-findings");
  data.warning_signs.forEach((sign) => {
    const item = element("li", `agent-finding finding-${sign.severity}`);
    item.append(element("span", "finding-marker", sign.severity === "info" ? "✓" : "!"));
    const copy = element("span", "finding-text");
    copy.append(element("b", "", sign.title), element("small", "", sign.detail));
    item.append(copy);
    findings.append(item);
  });
  bubble.append(findings);

  if (data.checked_urls.length) {
    bubble.append(element("h3", "agent-section-title url-section-title", "Visible link checks"));
    const urls = element("div", "agent-links");
    data.checked_urls.forEach((url) => {
      const row = element("div", "agent-link-row");
      row.append(element("span", "agent-link-domain", url.domain));
      row.append(element("span", url.risk >= 25 ? "agent-link-flagged" : "agent-link-clear", url.risk >= 25 ? `${url.risk} risk signals` : "No common flags"));
      urls.append(row);
      if (url.indicators.length) {
        const list = element("ul", "agent-link-indicators");
        url.indicators.forEach((indicator) => list.append(element("li", "", indicator)));
        urls.append(list);
      }
    });
    bubble.append(urls);
  }

  const advice = element("div", "agent-advice");
  advice.append(element("h3", "agent-section-title", "A safer next step"));
  advice.append(element("p", "", data.recommendations[0] || "Verify the request through an official channel you already trust."));
  bubble.append(advice);
  bubble.append(element("div", "agent-disclaimer", "Demo analysis · " + data.analysis_mode));
}

async function sendMessage(message) {
  const text = message.trim();
  if (!text || busy) return;
  addUserMessage(text);
  chatInput.value = "";
  busy = true;
  updateComposer();
  const thinking = addThinking();
  try {
    const response = await fetch(analyzeEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: text }),
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.detail || "The analysis could not be completed.");
    thinking.remove();
    const bubble = addAgentShell();
    renderAnalysis(bubble, payload);
  } catch (error) {
    thinking.remove();
    const bubble = addAgentShell();
    bubble.append(element("p", "agent-summary", error instanceof TypeError
      ? "I can’t reach the local analysis backend. Start the project server at http://127.0.0.1:8000, then try again."
      : (error.message || "The analysis could not be completed. Please try again.")));
  } finally {
    busy = false;
    updateComposer();
    chatInput.focus();
    scrollChat();
  }
}

chatInput.addEventListener("input", updateComposer);
chatInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault();
    chatForm.requestSubmit();
  }
});
chatForm.addEventListener("submit", (event) => {
  event.preventDefault();
  sendMessage(chatInput.value);
});
document.querySelectorAll("[data-sample]").forEach((button) => {
  button.addEventListener("click", () => {
    chatInput.value = samples[button.dataset.sample] || "";
    updateComposer();
    chatInput.focus();
  });
});
clearChatButton.addEventListener("click", () => {
  chatLog.innerHTML = '<article class="chat-row agent-row welcome-row"><div class="message-avatar" aria-hidden="true">P</div><div class="message-stack"><div class="message-byline">PhishGuard <span>DEMO AGENT</span></div><div class="agent-bubble welcome-bubble"><p>Hi, I can help you review a suspicious message. Paste the text or link below, and I’ll explain the signals I find.</p><div class="welcome-foot"><span class="welcome-spark">✳</span> I analyze locally and don’t open links.</div></div></div></article>';
  chatInput.value = "";
  updateComposer();
});
updateComposer();
