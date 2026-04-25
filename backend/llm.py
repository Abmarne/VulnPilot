import os
import json
import time
import re
from importlib import import_module
from typing import List, Dict, Any, Optional, Callable, cast
import requests

def _load_attr(module_name: str, attr_name: str) -> Any:
    try:
        module = import_module(module_name)
        return getattr(module, attr_name, None)
    except ImportError:
        return None

# Initial lazy loading of standard clients
load_dotenv = cast(Optional[Callable[[], None]], _load_attr("dotenv", "load_dotenv"))
genai = _load_attr("google.genai", "Client")
Groq = _load_attr("groq", "Groq")
OpenAI = _load_attr("openai", "OpenAI")
Anthropic = _load_attr("anthropic", "Anthropic")
InferenceClient = _load_attr("huggingface_hub", "InferenceClient")

if load_dotenv is not None:
    # Try multiple common locations
    candidates = [
        ".env",
        "backend/.env",
        os.path.join(os.path.dirname(__file__), ".env"),
        os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
    ]
    for path in candidates:
        if os.path.exists(path):
            print(f"[LLM] Found .env at: {os.path.abspath(path)}")
            load_dotenv(path)
            if os.environ.get("HF_API_KEY") or os.environ.get("GROQ_API_KEY"):
                break

# Manual fallback parser if dotenv is missing or failing
if not os.environ.get("HF_API_KEY"):
    for path in [".env", "backend/.env", os.path.join(os.path.dirname(__file__), ".env")]:
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    for line in f:
                        if '=' in line and not line.startswith('#'):
                            k, v = line.strip().split('=', 1)
                            os.environ[k.strip()] = v.strip().strip('"').strip("'")
            except: pass

# ── Dynamic Provider Fallback logic ──────────────────────────────────────────

def get_best_default_provider() -> Dict[str, str]:
    """Determines the best provider based on available environment variables.
    Priority: HuggingFace (Stable) -> Groq (Fallback)
    """
    if os.environ.get("HF_API_KEY"):
        return {
            "provider": "huggingface",
            "model": "Qwen/Qwen2.5-72B-Instruct",
            "api_key": os.environ["HF_API_KEY"]
        }
    if os.environ.get("GROQ_API_KEY"):
        return {
            "provider": "groq", 
            "model": "llama-3.1-8b-instant", 
            "api_key": os.environ["GROQ_API_KEY"]
        }
    return {
        "provider": "huggingface",
        "model": "Qwen/Qwen2.5-72B-Instruct",
        "api_key": ""
    }

print(f"[LLM] Initializing provider registry. Fallback mode: {'Base (HF/Groq)'}")

def _call_huggingface(prompt: str, api_key: str, model: str) -> str:
    """Default free provider fallback."""
    # Use a public, non-gated model as the safe default
    safe_model = model or "Qwen/Qwen2.5-72B-Instruct"
    try:
        if not api_key:
            client = InferenceClient(safe_model)
        else:
            client = InferenceClient(safe_model, token=api_key)
        
        response = ""
        for message in client.chat_completion(
            messages=[{"role": "user", "content": prompt}],
            max_tokens=2048,
            stream=True,
        ):
            if message.choices and len(message.choices) > 0:
                content = message.choices[0].delta.content
                if content:
                    response += content
        return response
    except Exception as e:
        print(f"[!] Hugging Face failure: {e}")
        return f"Error: {e}"

def _call_gemini_dynamic(prompt: str, api_key: str, model: str) -> str:
    if not genai: return "Error: google-genai not installed"
    try:
        client = genai(api_key=api_key)
        response = client.models.generate_content(
            model=model or "gemini-2.0-flash",
            contents=prompt
        )
        return response.text or "Error: Empty response from Gemini"
    except Exception as e:
        return f"Error: {e}"

def _call_groq_dynamic(prompt: str, api_key: str, model: str) -> str:
    if not Groq: return "Error: groq not installed"
    # Reduced retries for faster failover to HuggingFace
    for attempt in range(2):
        try:
            client = Groq(api_key=api_key)
            response = client.chat.completions.create(
                model=model or "llama-3.1-8b-instant",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
            )
            if response.choices and len(response.choices) > 0:
                return response.choices[0].message.content or ""
            return "Error: Empty response from Groq"
        except Exception as e:
            err_msg = str(e)
            if "429" in err_msg or "rate_limit" in err_msg.lower():
                wait_time = 2 # Fixed low wait for fast failover
                print(f"[LLM] Groq Rate Limit (429). Waiting {wait_time}s (Attempt {attempt+1}/2)...")
                time.sleep(wait_time)
                continue
            return f"Error: {e}"
    return "Error: Groq Rate Limit exceeded after 2 retries."

def _call_openai_dynamic(prompt: str, api_key: str, model: str) -> str:
    if not OpenAI: return "Error: openai not installed"
    try:
        client = OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model=model or "gpt-4o",
            messages=[{"role": "user", "content": prompt}],
        )
        return response.choices[0].message.content or ""
    except Exception as e:
        return f"Error: {e}"

def _call_anthropic_dynamic(prompt: str, api_key: str, model: str) -> str:
    if not Anthropic: return "Error: anthropic not installed"
    try:
        client = Anthropic(api_key=api_key)
        response = client.messages.create(
            model=model or "claude-3-5-sonnet-20240620",
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.content[0].text or "" # type: ignore
    except Exception as e:
        return f"Error: {e}"

def _call_llm(prompt: str, config: Optional[Dict] = None, _depth: int = 0) -> str:
    """Dispatches call to appropriate provider based on config with automated fallback.
    _depth guards against infinite recursion when all providers fail.
    """
    if _depth >= 2:
        print("[LLM] Circuit breaker triggered — all providers failed. Returning error.")
        return "Error: All LLM providers exhausted. Check your API keys or rate limits."
    
    cfg = config or {}
    provider = cfg.get("provider", "").lower()
    api_key = cfg.get("api_key", "")
    model = cfg.get("model", "")

    # 1. Resolve API Key & Provider
    if not provider:
        default_cfg = get_best_default_provider()
        provider = default_cfg["provider"]
        api_key = api_key or default_cfg["api_key"]
        model = model or default_cfg["model"]
    
    # 2. If no key was provided in UI, look in Environment
    if not api_key:
        env_map = {
            "gemini": "GOOGLE_API_KEY",
            "groq": "GROQ_API_KEY",
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
            "huggingface": "HF_API_KEY"
        }
        env_key_name = env_map.get(provider)
        if env_key_name:
            api_key = os.environ.get(env_key_name, "")

    # 3. Safe model defaults — never use gated models as defaults
    if provider == "huggingface" and not model:
        model = "Qwen/Qwen2.5-72B-Instruct"

    # 4. Final Fallback check
    if not api_key and provider not in ("huggingface",):
        print(f"[LLM] Warning: No key for {provider}. Falling back to system default...")
        default_cfg = get_best_default_provider()
        if default_cfg["provider"] != provider:
            return _call_llm(prompt, default_cfg, _depth + 1)

    # 5. Execute
    result = ""
    try:
        if provider == "huggingface":
            result = _call_huggingface(prompt, api_key, model)
        elif provider == "gemini":
            result = _call_gemini_dynamic(prompt, api_key, model)
        elif provider == "groq":
            result = _call_groq_dynamic(prompt, api_key, model)
        elif provider == "openai":
            result = _call_openai_dynamic(prompt, api_key, model)
        elif provider == "anthropic":
            result = _call_anthropic_dynamic(prompt, api_key, model)
        else:
            result = _call_huggingface(prompt, os.environ.get("HF_API_KEY", ""), "Qwen/Qwen2.5-72B-Instruct")
    except Exception as e:
        print(f"[LLM] Dispatcher Critical Error in {provider}: {e}")
        result = f"Error: {e}"

    # Automated Fallback: rate-limit on Groq → try HuggingFace once
    if result.startswith("Error:"):
        if ("429" in result or "rate limit" in result.lower()) and provider == "groq":
            if _depth < 1:
                print("[LLM] Groq hard rate-limit. Switching to HuggingFace fallback.")
                return _call_llm(prompt, {"provider": "huggingface", "model": "Qwen/Qwen2.5-72B-Instruct"}, _depth + 1)
        elif config is not None and _depth < 1:
            print(f"[LLM] {provider} failed ({result[:60]}). Retrying with system default...")
            return _call_llm(prompt, None, _depth + 1)
    
    return result

def autopilot_reasoning(prompt: str, config: Optional[Dict] = None) -> str:
    return _call_llm(prompt, config)

# Alias for backward compat
_call_gemini = _call_llm

def _parse_gemini_json(text: str) -> List[Any]:
    text = text.strip()
    text = re.sub(r'^```(?:json)?', '', text)
    text = re.sub(r'```$', '', text)
    text = text.strip()
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        try:
            parsed = json.loads(text, strict=False)
        except json.JSONDecodeError:
            repaired_text = re.sub(r'(?<!\\)\\(?!["\\/bfnrt]|u[0-9a-fA-F]{4})', r'\\\\', text)
            try:
                parsed = json.loads(repaired_text, strict=False)
            except json.JSONDecodeError:
                start = text.find("[")
                end = text.rfind("]") + 1
                if start != -1 and end > start:
                    try:
                        parsed = json.loads(text[start:end], strict=False)
                    except json.JSONDecodeError:
                        return []
                else:
                    start = text.find("{")
                    end = text.rfind("}") + 1
                    if start != -1 and end > start:
                        try:
                            parsed = json.loads(text[start:end], strict=False)
                        except json.JSONDecodeError:
                            return []
                    else:
                        return []
    if isinstance(parsed, dict):
        return [parsed]
    if isinstance(parsed, list):
        return cast(List[Any], parsed)
    return []

def _normalize_string_list(values: Any) -> List[str]:
    normalized: List[str] = []
    if not isinstance(values, list):
        return normalized
    for value in values:
        if isinstance(value, str):
            normalized.append(value)
        elif isinstance(value, dict):
            normalized.append(str(next(iter(value.values()), "")))
        else:
            normalized.append(str(value))
    return [value for value in normalized if value]

def generate_fuzzing_payloads(target_urls: List[str], schema_context: Dict[str, Any] = None, llm_config: Optional[Dict] = None) -> List[str]:
    import json
    schema_info = ""
    if schema_context and any(schema_context.values()):
        schema_info = f"\nEMPIRICAL APPLICATION SCHEMA:\n{json.dumps(schema_context, indent=2)}\n"
    prompt = f"""
    Generate 10 highly effective, BENIGN testing payloads for: {target_urls}
    {schema_info}
    Respond ONLY as a valid JSON array of strings.
    """
    try:
        text = _call_llm(prompt, llm_config)
        raw_payloads = _parse_gemini_json(text)
        clean_payloads = _normalize_string_list(raw_payloads)
        if clean_payloads: return clean_payloads
    except:
        pass
    return ["' OR 1=1 --", "<script>alert(1)</script>", "../../etc/passwd"]

def identify_sinks(code_context: str, llm_config: Optional[Dict] = None) -> List[Dict[str, Any]]:
    prompt = f"""
    Analyze the following code for security Sinks, data leakage, and logic flaws.
    For each discovery, provide a detailed finding object with:
    - vulnerability_type: (string)
    - severity: Critical, High, Medium, or Low (string)
    - explanation: (string) Concise description of the line(s) involved.
    - impact: (string) Explain EXACTLY how this causes a bug or security vulnerability. What is at risk?
    - exploit_scenario: (string) Step-by-step of how to trigger this.
    - manual_poc: (string) A curl command or python snippet that proves the bug.
    - remediation_steps: (string) Actionable fix instructions.
    - url_pattern: (string) The relative file path.
    - required_context: (list of strings) Any other files needed to trace this.

    Respond ONLY in JSON array format.
    SOURCE:
    {code_context}
    """
    try:
        text = _call_llm(prompt, llm_config)
        if text.startswith("Error:"):
            print(f"[!] SAST LLM Error: {text}")
            return []
        sinks = _parse_gemini_json(text)
        return [sink for sink in sinks if isinstance(sink, dict)]
    except Exception as e:
        print(f"[!] SAST parsing error: {e}")
        return []

def identify_secrets(code_context: str, llm_config: Optional[Dict] = None) -> List[Dict[str, Any]]:
    """Analyzes code and configuration files for leaked secrets, API keys, and credentials."""
    prompt = f"""
    --- SYSTEM ---
    You are a high-precision Secret Scanning Engine. Your goal is to identify hardcoded credentials, API keys, private keys, and tokens.
    
    --- TASK ---
    Analyze the following source code and configuration files for leaked secrets.
    For each discovery, provide a detailed finding object with:
    - vulnerability_type: (string) e.g., "Hardcoded API Key", "Leaked Private Key"
    - severity: Critical (for real keys), High (for suspicious tokens)
    - explanation: (string) Identify the line and what type of secret it appears to be.
    - impact: (string) Explain what an attacker can do with this secret.
    - exploit_scenario: (string) How to use this secret.
    - manual_poc: (string) The secret itself or a redacted version if it's too long.
    - remediation_steps: (string) How to rotate and move this to environment variables or a vault.
    - url_pattern: (string) The relative file path.

    Respond ONLY in JSON array format.
    SOURCE:
    {code_context}
    """
    try:
        text = _call_llm(prompt, llm_config)
        if text.startswith("Error:"):
            print(f"[!] Secrets LLM Error: {text}")
            return []
        secrets = _parse_gemini_json(text)
        return [s for s in secrets if isinstance(s, dict)]
    except Exception as e:
        print(f"[!] Secrets parsing error: {e}")
        return []

def reconstruct_api_schema(js_content: str, llm_config: Optional[Dict] = None) -> List[Dict[str, Any]]:
    prompt = f"Find API endpoints in JS. Respond ONLY in JSON array.\nJS:\n{js_content[:15000]}"
    try:
        text = _call_llm(prompt, llm_config)
        endpoints = _parse_gemini_json(text)
        return [endpoint for endpoint in endpoints if isinstance(endpoint, dict)]
    except:
        return []

def deep_taint_audit(vulnerability_chain: Dict[str, Any], extra_context: str, llm_config: Optional[Dict] = None) -> Dict[str, Any]:
    prompt = f"Audit Taint Chain. Respond in JSON object.\nFINDING: {vulnerability_chain}\nCONTEXT: {extra_context[:10000]}"
    try:
        text = _call_llm(prompt, llm_config)
        verdict = _parse_gemini_json(text)
        if verdict: return verdict[0]
    except:
        pass
    return {}

def generate_bespoke_payloads(sink_context: Dict[str, Any], llm_config: Optional[Dict] = None) -> List[str]:
    prompt = f"Generate 5 bypass payloads for: {sink_context}\nReturn JSON list."
    try:
        text = _call_llm(prompt, llm_config)
        payloads = _parse_gemini_json(text)
        return _normalize_string_list(payloads)
    except:
        return []

def get_refactored_file(original_code: str, vulnerability_details: Dict[str, Any], llm_config: Optional[Dict] = None) -> str:
    prompt = f"Refactor this file to fix the bug: {vulnerability_details}\nCODE:\n{original_code}\nRespond ONLY with code."
    try:
        text = _call_llm(prompt, llm_config)
        text = re.sub(r'^```[a-zA-Z]*\n', '', text)
        text = re.sub(r'\n```$', '', text)
        return text.strip()
    except:
        return original_code

def analyze_anomalies(anomalies: List[Dict[str, Any]], llm_config: Optional[Dict] = None) -> List[Dict[str, Any]]:
    results = []
    if not anomalies: return results
    for anomaly in anomalies:
        prompt = f"""
        Analyze this DAST anomaly discovered during security testing:
        ANOMALY: {anomaly}

        Provide a structured security finding including:
        - vulnerability_type: (string)
        - severity: Critical, High, Medium, or Low (string)
        - explanation: (string) Why do you think this is a real vulnerability?
        - impact: (string) What can happen if this is exploited?
        - exploit_scenario: (string) How can an attacker use this anomaly?
        - manual_poc: (string) The specific request/payload that triggers it.
        - remediation_steps: (string) How to fix the underlying app.

        Respond ONLY as a JSON object.
        """
        try:
            text = _call_llm(prompt, llm_config)
            analysis = _parse_gemini_json(text)
            if analysis: results.append({**anomaly, **analysis[0]})
        except:
            results.append(anomaly)
    return results

def analyze_hybrid(anomalies: List[Dict[str, Any]], code_context: str, llm_config: Optional[Dict] = None) -> List[Dict[str, Any]]:
    # Simplified hybrid for dynamic config
    all_findings = identify_sinks(code_context, llm_config)
    dast_findings = analyze_anomalies(anomalies, llm_config)
    return all_findings + dast_findings
