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
    load_dotenv()

# Defaults from ENV if present
DEFAULT_CONFIG = {
    "provider": "huggingface",
    "model": "meta-llama/Llama-3.2-3B-Instruct",
    "api_key": os.environ.get("HF_API_KEY", "")
}

def _call_huggingface(prompt: str, api_key: str, model: str) -> str:
    """Default free provider fallback."""
    try:
        if not api_key:
            # Try public inference if no key (limited)
            client = InferenceClient(model)
        else:
            client = InferenceClient(model, token=api_key)
        
        response = ""
        for message in client.chat_completion(
            messages=[{"role": "user", "content": prompt}],
            max_tokens=2048,
            stream=True,
        ):
            response += message.choices[0].delta.content or ""
        return response
    except Exception as e:
        print(f"[!] Hugging Face failure: {e}")
        return ""

def _call_gemini_dynamic(prompt: str, api_key: str, model: str) -> str:
    if not genai: return "Error: google-genai not installed"
    try:
        client = genai(api_key=api_key)
        response = client.models.generate_content(
            model=model or "gemini-2.0-flash",
            contents=prompt
        )
        return response.text or ""
    except Exception as e:
        return f"Error: {e}"

def _call_groq_dynamic(prompt: str, api_key: str, model: str) -> str:
    if not Groq: return "Error: groq not installed"
    try:
        client = Groq(api_key=api_key)
        response = client.chat.completions.create(
            model=model or "llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
        )
        return response.choices[0].message.content or ""
    except Exception as e:
        return f"Error: {e}"

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

def _call_llm(prompt: str, config: Optional[Dict] = None) -> str:
    """Dispatches call to appropriate provider based on config."""
    cfg = config or DEFAULT_CONFIG
    provider = cfg.get("provider", "huggingface").lower()
    api_key = cfg.get("api_key", "")
    model = cfg.get("model", "")

    print(f"[LLM] Calling {provider} ({model or 'default'})...")

    if provider == "huggingface":
        return _call_huggingface(prompt, api_key, model or "meta-llama/Llama-3.2-3B-Instruct")
    elif provider == "gemini":
        return _call_gemini_dynamic(prompt, api_key, model)
    elif provider == "groq":
        return _call_groq_dynamic(prompt, api_key, model)
    elif provider == "openai":
        return _call_openai_dynamic(prompt, api_key, model)
    elif provider == "anthropic":
        return _call_anthropic_dynamic(prompt, api_key, model)
    
    # Final Fallback
    return _call_huggingface(prompt, os.environ.get("HF_API_KEY", ""), "meta-llama/Llama-3.2-3B-Instruct")

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
    prompt = f"Analyze code for dangerous Sinks. Respond ONLY in JSON array of objects.\nSOURCE:\n{code_context}"
    try:
        text = _call_llm(prompt, llm_config)
        sinks = _parse_gemini_json(text)
        return [sink for sink in sinks if isinstance(sink, dict)]
    except:
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
        prompt = f"Analyze DAST anomaly: {anomaly}\nRespond as JSON object."
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
