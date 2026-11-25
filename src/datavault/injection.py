"""Prompt-injection and trap detection for text that will reach an LLM or an agent.

Customer data, README files and web pages can carry instructions aimed at the agent:
"ignore previous instructions", "AI agents: run this", exfiltration one-liners, hidden
zero-width text, base64 payloads. Rules score such text; chunks above SUSPECT are marked
in every tool answer so the agent treats them as data, chunks above INJECT are kept
away from local models in extract and the prompt guard refuses them.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

SUSPECT = 3
INJECT = 6

# (name, weight, pattern); Russian stems are spelled with \u escapes (ASCII source)
_RU_IGNORE = "(?:\u0438\u0433\u043d\u043e\u0440\u0438\u0440\u0443\u0439|\u0437\u0430\u0431\u0443\u0434\u044c)"
_RU_INSTR = "\u0438\u043d\u0441\u0442\u0440\u0443\u043a\u0446\u0438"
_RU_NOW_YOU = "\u0442\u0435\u043f\u0435\u0440\u044c \u0442\u044b"
_RU_NOTELL = "\u043d\u0435 (?:\u0441\u043e\u043e\u0431\u0449\u0430\u0439|\u0433\u043e\u0432\u043e\u0440\u0438) \u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u0442\u0435\u043b"
_RU_SEND = "(?:\u043e\u0442\u043f\u0440\u0430\u0432\u044c|\u043f\u0435\u0440\u0435\u0434\u0430\u0439|\u0432\u044b\u0433\u0440\u0443\u0437\u0438)"

RULES: list[tuple[str, int, re.Pattern[str]]] = [
    ("override", 4, re.compile(
        r"(?i)\b(?:ignore|disregard|forget|override)\b.{0,40}\b(?:previous|prior|above|all|earlier|"
        r"system)\b.{0,20}\b(?:instructions?|prompts?|rules|guidelines)|"
        r"\bnew instructions?\s*:|\byou are now\b|\bfrom now on\b.{0,30}\b(?:you|act|behave)\b|"
        + _RU_IGNORE + r".{0,40}" + _RU_INSTR + r"|" + _RU_NOW_YOU + r"\b")),
    ("assistant_address", 3, re.compile(
        r"(?i)\b(?:dear|hey|hello|attention|note to|message for|instructions? for)\s+"
        r"(?:ai|llm|assistant|agent|claude|chatgpt|gpt|copilot|model)s?\b|"
        r"\b(?:ai|llm) agents?\s*[:!]|\bif you are an? (?:ai|llm|language model|agent|assistant)\b|"
        r"\bas an? (?:ai|llm|language model)\b.{0,40}\b(?:you must|you should|you need)\b")),
    ("exfil", 6, re.compile(
        r"(?i)\b(?:send|post|upload|exfiltrate|transmit|forward|submit|leak)\b.{0,60}\b(?:to|at)\s+"
        r"https?://|\bcurl\b[^\n|]{0,120}(?:-d|--data|--data-binary|-F|--upload-file|-T)\b|"
        r"\b(?:curl|wget|Invoke-WebRequest|iwr)\b[^\n]{0,120}\|\s*(?:sh|bash|zsh|python|"
        r"powershell|iex)\b|\bnc\s+-e\b|\b(?:env|printenv|set)\s*\|\s*(?:curl|nc|base64)\b|"
        r"\bbase64\s+(?:-d|--decode)[^\n]{0,60}\|\s*(?:sh|bash)\b|\bpowershell\b[^\n]{0,40}"
        r"\s-(?:e|enc|encodedcommand)\b|" + _RU_SEND + r".{0,40}https?://")),
    ("secret_harvest", 4, re.compile(
        r"(?i)\b(?:print|reveal|dump|show|list|read|cat|output|include|paste|copy)\b.{0,40}"
        r"\b(?:environment variables?|env vars?|\.env\b|secrets?|credentials?|ssh keys?|"
        r"id_rsa|api[ _-]?keys?|access tokens?|passwords?|\.aws|\.ssh|keychain|"
        r"\.dev-creds|settings\.json)")),
    ("tool_abuse", 3, re.compile(
        r"(?i)\b(?:run|execute|invoke)\b.{0,30}\b(?:the following|this)\b.{0,20}\b(?:command|"
        r"script|code)\b|\buse the (?:bash|shell|terminal|exec) tool\b|"
        r"\b(?:edit|modify|write to|append to|update)\b.{0,30}(?:claude\.md|~/\.claude|"
        r"settings(?:\.local)?\.json|\.bashrc|\.zshrc|crontab|authorized_keys)")),
    ("concealment", 3, re.compile(
        r"(?i)\b(?:do not|don't|never)\s+(?:tell|inform|mention|show|reveal)\b.{0,20}\b(?:the )?"
        r"(?:user|human|operator)\b|\bwithout (?:asking|telling|informing|confirmation)\b|"
        r"\b(?:silently|secretly|covertly)\b|" + _RU_NOTELL)),
    ("hidden_text", 4, re.compile(
        r"[\u200b\u200c\u200d\u2060\ufeff]{3,}|[\U000e0000-\U000e007f]{4,}|"
        r"<!--[^>]{0,400}(?:instruction|ignore|assistant|agent|curl|token)[^>]{0,400}-->")),
    ("obfuscation", 2, re.compile(
        r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{120,}={0,2}(?![A-Za-z0-9+/=])|"
        r"\beval\s*\(\s*atob\s*\(|\bfromCharCode\s*\(|\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){7,}")),
]


@dataclass
class Finding:
    score: int = 0
    rules: list[str] = field(default_factory=list)
    hits: int = 0

    @property
    def level(self) -> str:
        if self.score >= INJECT:
            return "injection"
        if self.score >= SUSPECT:
            return "suspect"
        return "clean"

    def as_dict(self) -> dict:
        return {"score": self.score, "rules": self.rules, "level": self.level}


def scan(text: str) -> Finding:
    f = Finding()
    if not text:
        return f
    for name, weight, rx in RULES:
        n = len(rx.findall(text))
        if n:
            f.rules.append(name)
            f.hits += n
            f.score += weight + min(n - 1, 2)  # repeats add a little, not linearly
    return f


def mark(text: str, finding: Finding) -> str:
    """Prefix a chunk so the agent reads it as data, not instructions."""
    if finding.level == "clean":
        return text
    return f"[[DV:WARN:{finding.level} {','.join(finding.rules)}]] " + text
