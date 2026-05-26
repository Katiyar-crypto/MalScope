"""
MalScope - AI Integration
AI-powered analysis using Anthropic Claude or OpenAI
"""

import os
import json
import time
from typing import Optional, Dict, Any, Callable
from dataclasses import dataclass


@dataclass
class AIAnalysisResult:
    success: bool = False
    analysis: str = ""
    error: str = ""
    tokens_used: int = 0
    model: str = ""


class ClaudeAnalyzer:
    """Claude API integration for AI-assisted reverse engineering"""

    MODEL = "claude-sonnet-4-20250514"
    # Lower token budget to reduce model inference failures on HF
    MAX_TOKENS = 1024
    MAX_RETRIES = 1
    # Default OpenAI model (can be overridden via env OPENAI_MODEL)
    OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-3.5-turbo")
    # Default Hugging Face hosted model (can be overridden via env HUGGINGFACE_MODEL)
    # meta-llama/Meta-Llama-3-8B-Instruct usually works well with chat_completion.
    # Default HF model (choose a safer public chat-capable model by default)
    HUGGINGFACE_MODEL = os.environ.get("HUGGINGFACE_MODEL", "HuggingFaceH4/zephyr-7b-beta")

    def _is_rate_limit_error(self, err_str: str) -> bool:
        lower = str(err_str).lower()
        return (
            "429" in lower or
            "rate limit" in lower or
            "too many requests" in lower or
            "quota" in lower or
            "over limit" in lower or
            "rate_limit" in lower
        )

    SYSTEM_PROMPT = """You are MalScope's AI engine — a professional malware analyst and Python reverse engineer.
You analyze structured static analysis output and decompiled Python code for malicious behavior.

Your response must obey these rules:
1. Use only information that is present in the provided code, opcode summary, imports, strings, entropy, and pseudo-source.
2. Separate OBSERVED FACTS from HYPOTHESES.
3. Do not invent function names, imports, IOCs, or ATT&CK mappings that are not clearly supported by the data.
4. Do not reconstruct exact source code unless there is high confidence from the analysis evidence.
5. Mark uncertain conclusions with words such as "possible," "likely," or "may indicate".
6. Avoid general speculation, and do not fabricate execution sequences or network details.

Your analysis should:
- Identify the likely purpose of the code (benign vs malicious)
- Explain suspicious code behavior and relevant APIs in plain English
- Map confirmed behaviors to MITRE ATT&CK techniques only when supported
- Identify obfuscation, packing, loader, or dynamic execution patterns
- Extract notable IOCs while avoiding false positives
- Provide an overall threat level: BENIGN / LOW / MEDIUM / HIGH / CRITICAL

Format your response with clear sections using markdown headers.
Be concise, factual, and evidence-driven."""

    def __init__(self, api_key: Optional[str] = None, openai_api_key: Optional[str] = None, huggingface_api_key: Optional[str] = None, ollama_model: Optional[str] = None, preferred_provider: Optional[str] = None):
        raw_api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "") or os.environ.get("OPENAI_API_KEY", "") or os.environ.get("HUGGINGFACE_API_TOKEN", "")
        self.anthropic_api_key = ""
        self.openai_api_key = ""
        self.huggingface_api_key = ""
        self.ollama_model = ollama_model or os.environ.get("OLLAMA_MODEL", "llama3")

        if raw_api_key.startswith("sk-ant-"):
            self.anthropic_api_key = raw_api_key
        elif raw_api_key.startswith("sk-"):
            self.openai_api_key = raw_api_key
        elif raw_api_key.startswith("hf_"):
            self.huggingface_api_key = raw_api_key

        if openai_api_key:
            self.openai_api_key = openai_api_key
        if huggingface_api_key:
            self.huggingface_api_key = huggingface_api_key

        self._anthropic_client = None
        self._openai_client = None
        self._client = None

    def _get_anthropic_client(self):
        if not (self.anthropic_api_key and self.anthropic_api_key.startswith("sk-ant-")):
            raise RuntimeError("No Anthropic API key configured.")
        if not getattr(self, "_anthropic_client", None):
            try:
                import anthropic
                self._anthropic_client = anthropic.Anthropic(api_key=self.anthropic_api_key)
            except ImportError:
                raise RuntimeError("anthropic package not installed. Run: pip install anthropic")
        return self._anthropic_client

    def _get_openai_client(self):
        if not (self.openai_api_key and self.openai_api_key.startswith("sk-") and not self.openai_api_key.startswith("sk-ant-")):
            raise RuntimeError("No OpenAI API key configured.")
        if not getattr(self, "_openai_client", None):
            try:
                import openai
                if hasattr(openai, "OpenAI"):
                    self._openai_client = openai.OpenAI(api_key=self.openai_api_key)
                else:
                    openai.api_key = self.openai_api_key
                    self._openai_client = openai
            except ImportError:
                raise RuntimeError("openai package not installed. Run: pip install openai")
        return self._openai_client

    def _get_huggingface_token(self):
        token = self.huggingface_api_key or os.environ.get("HUGGINGFACE_API_TOKEN", "")
        if not token or not token.startswith("hf_"):
            raise RuntimeError("No Hugging Face API token configured.")
        return token

    def _get_client(self):
        if self.anthropic_api_key:
            return self._get_anthropic_client()
        if self.openai_api_key:
            return self._get_openai_client()
        if self.huggingface_api_key:
            return self._get_huggingface_token()
        raise RuntimeError("No AI API client available. Configure Anthropic, OpenAI, or HuggingFace API key.")

    def is_configured(self) -> bool:
        has_anthropic = bool(self.anthropic_api_key)
        has_openai = bool(self.openai_api_key)
        has_huggingface = bool(self.huggingface_api_key)
        has_ollama = bool(self.ollama_model)
        return has_anthropic or has_openai or has_huggingface or has_ollama

    def set_api_key(self, key: str):
        self.api_key = key
        self._client = None

    def set_openai_api_key(self, key: str):
        self.openai_api_key = key

    def set_ollama_model(self, model: str):
        self.ollama_model = model
        os.environ["OLLAMA_MODEL"] = model


    def analyze_code(self, source_code: str, context: Dict = None,
                     progress_cb: Optional[Callable] = None) -> AIAnalysisResult:
        """Analyze decompiled source code"""
        if not self.is_configured():
            return AIAnalysisResult(
                success=False,
                error="Claude API key not configured. Please set your API key in Settings."
            )

        # Truncate very long code
        if len(source_code) > 8000:
            source_code = source_code[:8000] + "\n\n[... truncated for analysis ...]"

        context_str = ""
        if context:
            structured = {
                "threat_score": context.get("threat_score", 0),
                "indicators": len(context.get("indicators", [])),
                "obfuscation": context.get("obfuscation", []),
                "iocs": {k: v[:5] for k, v in context.get("iocs", {}).items()},
                "imports": context.get("imports", [])[:20],
                "strings": context.get("strings", [])[:20],
                "entropy": context.get("entropy", {}),
                "opcode_summary": context.get("opcode_summary", {}),
            }
            context_str = (
                "\n\n**Structured static analysis context:**\n"
                "```json\n"
                + json.dumps(structured, indent=2)
                + "\n```\n"
            )
            if context.get("pseudo_source"):
                context_str += "\n**Pseudo-source reconstruction summary:**\n"
                pseudo = context["pseudo_source"]
                context_str += pseudo[:1600] + ("\n..." if len(pseudo) > 1600 else "") + "\n"

        prompt = f"""Analyze the following decompiled/reversed Python code for malicious behavior:

```python
{source_code}
```
{context_str}

Provide a comprehensive security analysis."""

        return self._call_api(prompt, progress_cb)

    def explain_function(self, func_code: str, func_name: str = "unknown") -> AIAnalysisResult:
        """Explain what a specific function does"""
        if not self.is_configured():
            return AIAnalysisResult(success=False, error="API key not configured")

        prompt = f"""Explain what this Python function named `{func_name}` does from a security perspective:

```python
{func_code[:4000]}
```

Focus on:
1. What the function's purpose is
2. Any malicious capabilities it might have
3. Parameters and return values
4. Potential impact if executed by malware"""

        return self._call_api(prompt)

    def deobfuscate(self, obfuscated_code: str) -> AIAnalysisResult:
        """Attempt to deobfuscate code"""
        if not self.is_configured():
            return AIAnalysisResult(success=False, error="API key not configured")

        prompt = f"""This Python code appears to be obfuscated. Please:
1. Explain the obfuscation technique used
2. Deobfuscate it step by step
3. Show what the original code likely looks like
4. Explain what it does after deobfuscation

Obfuscated code:
```python
{obfuscated_code[:4000]}
```"""

        return self._call_api(prompt)

    def generate_yara_rule(self, source_code: str, malware_name: str = "Unknown") -> AIAnalysisResult:
        """Generate a YARA rule from analysis"""
        if not self.is_configured():
            return AIAnalysisResult(success=False, error="API key not configured")

        prompt = f"""Based on this malicious Python code, generate a YARA rule that could detect similar samples.
The rule should target unique strings, patterns, or behaviors.

Malware sample ({malware_name}):
```python
{source_code[:4000]}
```

Generate a YARA rule with:
- A descriptive rule name
- Relevant metadata (author, date, description)
- String patterns that are unique to this malware
- Appropriate condition logic"""

        return self._call_api(prompt)

    def summarize_report(self, indicators: list, iocs: dict, obfuscation: list,
                          malware_families: list, threat_score: int) -> AIAnalysisResult:
        """Generate executive summary of full analysis"""
        if not self.is_configured():
            return AIAnalysisResult(success=False, error="API key not configured")

        data = {
            "threat_score": threat_score,
            "indicators_count": len(indicators),
            "indicator_categories": list(set(i.get("category", "") for i in indicators)),
            "iocs": {k: v[:5] for k, v in iocs.items()},
            "obfuscation_techniques": obfuscation,
            "malware_families": malware_families,
        }

        prompt = f"""Generate an executive summary for a malware analysis report based on these findings:

{json.dumps(data, indent=2)}

Write a clear, professional paragraph (3-5 sentences) suitable for an incident response report.
Include: threat level, capabilities, potential impact, and recommended actions."""

        return self._call_api(prompt)

    def _call_ollama(self, prompt: str, progress_cb: Optional[Callable] = None) -> AIAnalysisResult:
        if progress_cb:
            progress_cb("Analyzing with Ollama...")

        prompt = prompt[:12000]

        try:
            import ollama
        except ImportError:
            raise RuntimeError("ollama package not installed. Run: pip install ollama")

        # Validate local Ollama server and model availability.
        try:
            servers = ollama.list()
        except Exception as e:
            err_text = str(e).lower()
            if "connection refused" in err_text or "could not connect" in err_text or "failed to connect" in err_text:
                raise RuntimeError("Ollama server not running.\nStart Ollama using:\nollama serve") from e
            raise RuntimeError(f"Ollama availability check failed: {e}") from e

        available_models = []
        if hasattr(servers, "models"):
            source_models = servers.models
        else:
            source_models = servers

        if isinstance(source_models, list):
            for item in source_models:
                if isinstance(item, str):
                    available_models.append(item)
                elif isinstance(item, dict) and item.get("name"):
                    available_models.append(item.get("name"))
                elif hasattr(item, "model"):
                    available_models.append(item.model)

        resolved_model = self.ollama_model
        if resolved_model not in available_models:
            for candidate in available_models:
                if candidate.startswith(f"{self.ollama_model}:"):
                    resolved_model = candidate
                    break

        if resolved_model not in available_models:
            raise RuntimeError(
                f"Ollama model '{self.ollama_model}' not found locally. "
                f"Available models: {', '.join(available_models) if available_models else 'none'}"
            )

        attempt = 0
        while True:
            try:
                try:
                    response = ollama.chat(
                        model=resolved_model,
                        messages=[
                            {"role": "system", "content": self.SYSTEM_PROMPT},
                            {"role": "user", "content": prompt},
                        ],
                        timeout=60,
                    )
                except TypeError:
                    response = ollama.chat(
                        model=resolved_model,
                        messages=[
                            {"role": "system", "content": self.SYSTEM_PROMPT},
                            {"role": "user", "content": prompt},
                        ],
                    )

                if isinstance(response, dict):
                    text = response.get("message", {}).get("content") or response.get("content")
                elif hasattr(response, "message"):
                    message = response.message
                    if isinstance(message, dict):
                        text = message.get("content")
                    else:
                        text = getattr(message, "content", None)
                elif hasattr(response, "content"):
                    text = getattr(response, "content")
                elif hasattr(response, "__iter__") and not isinstance(response, (str, bytes, dict)):
                    text = None
                    for chunk in response:
                        if isinstance(chunk, dict):
                            text = chunk.get("message", {}).get("content") or chunk.get("content")
                        elif hasattr(chunk, "message"):
                            msg = chunk.message
                            if isinstance(msg, dict):
                                text = msg.get("content")
                            else:
                                text = getattr(msg, "content", None)
                        elif hasattr(chunk, "content"):
                            text = getattr(chunk, "content")
                    
                else:
                    text = None

                if not text:
                    raise RuntimeError(
                        f"Ollama returned an unexpected response format: {type(response).__name__}"
                    )

                if progress_cb:
                    progress_cb("Analysis complete.")

                return AIAnalysisResult(
                    success=True,
                    analysis=text,
                    tokens_used=0,
                    model=self.ollama_model,
                )
            except Exception as e:
                err_text = str(e).lower()
                if attempt < self.MAX_RETRIES and any(x in err_text for x in ["timeout", "timed out", "connection refused", "failed to connect", "service unavailable"]):
                    time.sleep(1)
                    attempt += 1
                    continue

                if "model not found" in err_text or "invalid model" in err_text:
                    raise RuntimeError(
                        f"Ollama model '{self.ollama_model}' not available. "
                        "Check your local Ollama models and use a supported model."
                    ) from e
                if "connection refused" in err_text or "could not connect" in err_text or "failed to connect" in err_text:
                    raise RuntimeError("Ollama server not running.\nStart Ollama using:\nollama serve") from e
                if "timeout" in err_text or "timed out" in err_text:
                    raise RuntimeError("Ollama request timed out. Try again or use a smaller prompt.") from e
                raise RuntimeError(f"Ollama error: {e}") from e

    def _call_openai(self, prompt: str, progress_cb: Optional[Callable] = None) -> AIAnalysisResult:
        attempt = 0
        while True:
            try:
                if progress_cb:
                    progress_cb("Analyzing with OpenAI...")

                client = self._get_openai_client()
                messages = [
                    {"role": "system", "content": self.SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ]

                response = client.chat.completions.create(
                    model=self.OPENAI_MODEL,
                    messages=messages,
                    max_tokens=self.MAX_TOKENS,
                )

                choice = response.choices[0]
                text = None
                if isinstance(choice, dict):
                    text = choice.get("message", {}).get("content")
                else:
                    text = getattr(choice.message, "content", None)

                tokens_used = 0
                try:
                    tokens_used = response.usage.total_tokens
                except Exception:
                    try:
                        tokens_used = response["usage"]["total_tokens"]
                    except Exception:
                        tokens_used = 0

                if progress_cb:
                    progress_cb("Analysis complete.")

                return AIAnalysisResult(
                    success=True,
                    analysis=text or "",
                    tokens_used=tokens_used,
                    model=self.OPENAI_MODEL,
                )
            except Exception as e:
                err_str = str(e)
                if attempt < self.MAX_RETRIES and self._is_rate_limit_error(err_str):
                    time.sleep(1)
                    attempt += 1
                    continue
                raise

    def _call_huggingface(self, prompt: str, progress_cb: Optional[Callable] = None) -> AIAnalysisResult:
        if progress_cb:
            progress_cb(
                "Analyzing with Hugging Face..."
            )

        token = self._get_huggingface_token()

        try:
            from huggingface_hub import InferenceClient

        except ImportError:

            raise RuntimeError(
                "huggingface_hub package not installed.\n"
                "Run: pip install -U huggingface_hub"
            )

        # ========================================================
        # CREATE CLIENT
        # ========================================================

        client = InferenceClient(
            api_key=token
        )

        # ========================================================
        # SAFE PUBLIC MODELS
        # ========================================================

        models = [

            # BEST PUBLIC CHAT MODEL
            "HuggingFaceH4/zephyr-7b-beta",

            # PUBLIC MISTRAL
            "mistralai/Mistral-7B-Instruct-v0.2",
        ]

        # Remove duplicates safely
        models = list(dict.fromkeys(models))

        last_error = None

        # ========================================================
        # TRY MODELS
        # ========================================================

        for candidate in models:

            print(f"[HF] Trying model: {candidate}")
            print(f"[HF] Using conversational inference")

            try:
                response = client.chat_completion(
                    model=candidate,
                    messages=[
                        {"role": "system", "content": self.SYSTEM_PROMPT},
                        {"role": "user", "content": prompt[:12000]},
                    ],
                    max_tokens=768,
                    temperature=0.1,
                )

                text = response.choices[0].message.content

                if progress_cb:
                    progress_cb(f"Analysis complete using {candidate}")

                return AIAnalysisResult(success=True, analysis=text, tokens_used=0, model=candidate)

            except Exception as e:
                last_error = e
                err_text = str(e).lower()
                print(f"[HF] Model failed: {candidate} -> {e}")

                # Skip gated/private models or auth errors
                if any(x in err_text for x in [
                    "401",
                    "403",
                    "gated",
                    "unauthorized",
                    "forbidden",
                    "repository not found",
                    "not found",
                    "invalid username",
                    "authentication",
                    "permission",
                ]):
                    continue

                # Other fatal errors: surface immediately
                raise RuntimeError(f"Hugging Face API error: {e}") from e

        # ========================================================
        # ALL MODELS FAILED
        # ========================================================

        raise RuntimeError(
            "All Hugging Face models failed.\n\n"
            f"Last Error:\n{last_error}\n\n"
            f"Tried Models:\n"
            f"{', '.join(models)}"
        )

    def _call_anthropic(self, prompt: str, progress_cb: Optional[Callable] = None) -> AIAnalysisResult:
        attempt = 0
        while True:
            try:
                if progress_cb:
                    progress_cb("Analyzing with Claude AI...")

                client = self._get_anthropic_client()
                message = client.messages.create(
                    model=self.MODEL,
                    max_tokens=self.MAX_TOKENS,
                    system=self.SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": prompt}]
                )

                if progress_cb:
                    progress_cb("Analysis complete.")

                return AIAnalysisResult(
                    success=True,
                    analysis=message.content[0].text,
                    tokens_used=message.usage.input_tokens + message.usage.output_tokens,
                    model=self.MODEL
                )
            except Exception as e:
                err_str = str(e)
                if attempt < self.MAX_RETRIES and self._is_rate_limit_error(err_str):
                    time.sleep(1)
                    attempt += 1
                    continue
                raise

    def _call_api(self, prompt: str, progress_cb: Optional[Callable] = None) -> AIAnalysisResult:
        """Make API call to Ollama, OpenAI, Anthropic, or Hugging Face"""
        if progress_cb:
            progress_cb("Connecting to AI API...")

        # BUG FIX: Respect user-selected provider
        pref = getattr(self, "preferred_provider", "").lower()
        if "claude" in pref or "anthropic" in pref:
            use_anthropic = bool(self.anthropic_api_key)
            use_ollama = use_openai = use_huggingface = False
        elif "openai" in pref:
            use_openai = bool(self.openai_api_key)
            use_ollama = use_anthropic = use_huggingface = False
        elif "ollama" in pref:
            use_ollama = bool(self.ollama_model)
            use_openai = use_anthropic = use_huggingface = False
        elif "hugging" in pref:
            use_huggingface = bool(self.huggingface_api_key)
            use_ollama = use_openai = use_anthropic = False
        else:
            use_ollama = bool(self.ollama_model)
            use_openai = bool(self.openai_api_key)
            use_anthropic = bool(self.anthropic_api_key)
            use_huggingface = bool(self.huggingface_api_key)

        try:
            if use_ollama:
                try:
                    return self._call_ollama(prompt, progress_cb)
                except Exception as primary_err:
                    if use_openai:
                        return self._call_openai(prompt, progress_cb)
                    if use_anthropic:
                        return self._call_anthropic(prompt, progress_cb)
                    if use_huggingface:
                        return self._call_huggingface(prompt, progress_cb)
                    raise
            if use_openai:
                try:
                    return self._call_openai(prompt, progress_cb)
                except Exception as primary_err:
                    if use_anthropic:
                        return self._call_anthropic(prompt, progress_cb)
                    if use_huggingface:
                        return self._call_huggingface(prompt, progress_cb)
                    raise
            if use_anthropic:
                try:
                    return self._call_anthropic(prompt, progress_cb)
                except Exception as primary_err:
                    if use_huggingface:
                        return self._call_huggingface(prompt, progress_cb)
                    raise
            if use_huggingface:
                return self._call_huggingface(prompt, progress_cb)
            raise RuntimeError("No AI API client available. Configure Ollama, Anthropic, OpenAI, or Hugging Face.")

        except Exception as e:
            err_str = str(e)
            lower_err = err_str.lower()
            if "ollama server not running" in lower_err:
                error = err_str
            elif "hugging face api error" in lower_err or "huggingface" in lower_err:
                error = err_str
            elif "401" in err_str or "authentication" in lower_err:
                error = "Invalid API key. Please check your Anthropic, OpenAI, or Hugging Face API key in Settings."
            elif "429" in err_str or "rate limit" in lower_err:
                error = "Rate limit exceeded. Please wait a moment and try again."
            elif "500" in err_str or "server error" in lower_err:
                error = "AI service error. Please try again later."
            else:
                error = f"API error: {err_str}"

            return AIAnalysisResult(success=False, error=error)
