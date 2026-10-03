"""Tiny bundled Multinomial Naive Bayes model for the offline demo.

This is intentionally dependency-free. The starter examples make the project
demonstrable; they are not a substitute for a representative, reviewed dataset.
"""

from __future__ import annotations

import math
import re
from collections import Counter


SCAM_EXAMPLES = [
    "Your account is suspended verify your password immediately using this link",
    "Congratulations you have won a free gift card claim your prize today",
    "Your parcel delivery failed pay a small fee to release your package",
    "Unusual sign in activity confirm your identity now to avoid account closure",
    "Final notice invoice overdue make payment today using wire transfer",
    "Reply with your one time code to secure your bank account",
    "Your PayPal account is limited validate your login credentials immediately",
    "Tax refund available click this link to claim your refund",
    "Work from home earn cash send a crypto wallet payment to get started",
    "Your subscription payment failed update billing details to avoid cancellation",
    "Urgent gift card payment required for your manager today",
    "Package held by customs pay a processing fee here now",
    "Your bank transfer is blocked verify your account immediately",
    "You have been selected as a winner claim your prize and provide details",
    "Security alert confirm your password to restore access",
    "Dear user your account is locked click here and verify now",
    "Your mobile number will be disconnected verify your details immediately",
    "We detected suspicious activity send your security code to unlock your profile",
    "Exclusive reward waiting claim your free voucher before it expires",
    "The payment could not be delivered send money again to this wallet",
    "Your account will close today click the secure login link to keep access",
    "Pay the delivery charge to receive your parcel reply with your card details",
    "Your online banking access is frozen reset your password through this link",
    "Act now to receive your guaranteed cash prize and avoid losing it",
]

BENIGN_EXAMPLES = [
    "Hi team are we still meeting at three in the conference room",
    "Your library book is due next Friday renew it at the front desk",
    "Thanks for your order it has shipped and should arrive Thursday",
    "Reminder your appointment is confirmed for Tuesday at ten am",
    "Here are the notes from today's planning meeting",
    "Your monthly statement is ready in the official app please sign in as usual",
    "Can you send the presentation before our project review",
    "Your package is on its way track it in the retailer app",
    "The school science exhibition begins at nine this Saturday",
    "Your subscription renews on the fifteenth manage settings in your account",
    "Payment of your electricity bill was received receipt attached",
    "Please review the attached draft and send feedback when you can",
    "Your account settings were changed contact support if you did not make this change",
    "Thank you for contacting customer support we will reply within two business days",
    "Your reservation is confirmed we look forward to seeing you",
    "Your password was changed successfully if this was not you open the app",
    "The team lunch is booked for noon please let me know about dietary needs",
    "Attached is the invoice from our meeting please process it through the usual portal",
    "Your order has been delivered to the address you provided",
    "The monthly newsletter is available on our website",
    "Please call me when you have time to discuss the schedule",
    "Your appointment reminder is for tomorrow at 2 pm",
    "The project files are in the shared folder for your review",
    "Your payment was received and the receipt is available in your account",
]


def _tokens(text: str) -> list[str]:
    return re.findall(r"[a-z]{2,}", text.lower())


class NaiveBayesTextClassifier:
    """A compact Multinomial Naive Bayes model trained from bundled examples."""

    def __init__(self, scam_examples: list[str], benign_examples: list[str]) -> None:
        self.examples = {"scam": scam_examples, "benign": benign_examples}
        self.word_counts = {label: Counter() for label in self.examples}
        self.token_totals = Counter()
        self.vocabulary: set[str] = set()
        for label, examples in self.examples.items():
            for example in examples:
                words = _tokens(example)
                self.word_counts[label].update(words)
                self.token_totals[label] += len(words)
                self.vocabulary.update(words)
        self.priors = {
            label: math.log(len(examples) / sum(map(len, self.examples.values())))
            for label, examples in self.examples.items()
        }

    def scam_probability(self, text: str) -> float:
        words = _tokens(text)
        if not words:
            return 0.5
        vocab_size = max(1, len(self.vocabulary))
        log_scores = dict(self.priors)
        for label in log_scores:
            denominator = self.token_totals[label] + vocab_size
            counts = self.word_counts[label]
            log_scores[label] += sum(
                math.log((counts[word] + 1) / denominator)
                for word in words
                if word in self.vocabulary
            )
        difference = max(-60.0, min(60.0, log_scores["benign"] - log_scores["scam"]))
        return 1.0 / (1.0 + math.exp(difference))


MODEL = NaiveBayesTextClassifier(SCAM_EXAMPLES, BENIGN_EXAMPLES)
