import json
import re
import shlex
import yaml
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from profile_store import normalize_target_host


SKIP_HEADERS = {"content-length", "host"}


def _normalized_url(url: str) -> str:
    parsed = urlparse(url)
    clean_query = urlencode([(key, value) for key, value in parse_qsl(parsed.query, keep_blank_values=True)], doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, clean_query, parsed.fragment))


def _url_without_query(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", parsed.fragment))


def _list_to_dict(items: List[Dict[str, Any]], name_key: str = "name", value_key: str = "value") -> Dict[str, str]:
    data: Dict[str, str] = {}
    for item in items:
        name = str(item.get(name_key, "")).strip()
        if not name:
            continue
        data[name] = str(item.get(value_key, ""))
    return data


def _normalize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    return {
        key: value
        for key, value in headers.items()
        if key and key.lower() not in SKIP_HEADERS and value is not None
    }


def _detect_body(body_text: str, content_type: str) -> Dict[str, Any]:
    body_text = body_text or ""
    content_type = (content_type or "").lower()

    if not body_text:
        return {
            "body_type": "none",
            "body_text": "",
            "form_fields": [],
            "json_fields": [],
            "fuzzable": True,
        }

    if "multipart/form-data" in content_type:
        return {
            "body_type": "multipart",
            "body_text": body_text,
            "form_fields": [],
            "json_fields": [],
            "fuzzable": False,
        }

    if "application/json" in content_type:
        try:
            parsed = json.loads(body_text)
            if isinstance(parsed, dict):
                json_fields = [
                    key for key, value in parsed.items()
                    if isinstance(value, (str, int, float, bool)) or value is None
                ]
                return {
                    "body_type": "json",
                    "body_text": body_text,
                    "form_fields": [],
                    "json_fields": json_fields,
                    "fuzzable": True,
                }
        except json.JSONDecodeError:
            pass

    if "application/x-www-form-urlencoded" in content_type:
        form_fields = [key for key, _ in parse_qsl(body_text, keep_blank_values=True)]
        return {
            "body_type": "form",
            "body_text": body_text,
            "form_fields": form_fields,
            "json_fields": [],
            "fuzzable": True,
        }

    return {
        "body_type": "raw",
        "body_text": body_text,
        "form_fields": [],
        "json_fields": [],
        "fuzzable": True,
    }


def _normalize_request(
    *,
    method: str,
    url: str,
    headers: Dict[str, str],
    cookies: Dict[str, str],
    body_text: str,
    request_name: str,
    source_type: str,
) -> Optional[Dict[str, Any]]:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None

    content_type = headers.get("Content-Type") or headers.get("content-type", "")
    query_json = {key: value for key, value in parse_qsl(parsed.query, keep_blank_values=True)}
    body_info = _detect_body(body_text, content_type)
    return {
        "method": method.upper() or "GET",
        "url": _url_without_query(_normalized_url(url)),
        "headers_json": _normalize_headers(headers),
        "query_json": query_json,
        "body_text": body_info["body_text"],
        "body_type": body_info["body_type"],
        "cookies_json": cookies,
        "request_name": request_name or parsed.path or parsed.netloc,
        "content_type": content_type,
        "form_fields": body_info["form_fields"],
        "json_fields": body_info["json_fields"],
        "fuzzable": body_info["fuzzable"],
        "source": source_type,
    }


def parse_har_content(content: bytes, target: str, filename: str = "Imported HAR") -> Dict[str, Any]:
    target_host = normalize_target_host(target)
    payload = json.loads(content.decode("utf-8", errors="ignore"))
    entries = payload.get("log", {}).get("entries", [])
    requests: List[Dict[str, Any]] = []

    for entry in entries:
        request = entry.get("request", {})
        url = str(request.get("url", "")).strip()
        if not url:
            continue
        if normalize_target_host(url) != target_host:
            continue

        headers = _list_to_dict(request.get("headers", []))
        cookies = _list_to_dict(request.get("cookies", []))
        post_data = request.get("postData", {}) or {}
        body_text = str(post_data.get("text", ""))
        normalized = _normalize_request(
            method=str(request.get("method", "GET")),
            url=url,
            headers=headers,
            cookies=cookies,
            body_text=body_text,
            request_name=urlparse(url).path or filename,
            source_type="har",
        )
        if normalized:
            requests.append(normalized)

    if not requests:
        raise ValueError("No matching HTTP requests for the selected target were found in the HAR file.")

    return {
        "name": filename.rsplit(".", 1)[0] or "Imported HAR",
        "source_type": "har",
        "requests": requests,
    }


def parse_curl_command(command: str, target: str, name: Optional[str] = None) -> Dict[str, Any]:
    tokens = shlex.split(command, posix=True)
    if not tokens:
        raise ValueError("Empty cURL command.")

    method = "GET"
    headers: Dict[str, str] = {}
    cookies: Dict[str, str] = {}
    body_text = ""
    url = ""
    idx = 0

    while idx < len(tokens):
        token = tokens[idx]
        next_value = tokens[idx + 1] if idx + 1 < len(tokens) else ""

        if token == "curl":
            idx += 1
            continue
        if token in {"-X", "--request"} and next_value:
            method = next_value.upper()
            idx += 2
            continue
        if token in {"-H", "--header"} and next_value:
            if ":" in next_value:
                header_name, header_value = next_value.split(":", 1)
                headers[header_name.strip()] = header_value.strip()
            idx += 2
            continue
        if token in {"-d", "--data", "--data-raw", "--data-binary", "--data-urlencode"} and next_value:
            body_text = next_value
            if method == "GET":
                method = "POST"
            idx += 2
            continue
        if token in {"-b", "--cookie"} and next_value:
            for part in next_value.split(";"):
                if "=" in part:
                    cookie_name, cookie_value = part.split("=", 1)
                    cookies[cookie_name.strip()] = cookie_value.strip()
            idx += 2
            continue
        if token == "--url" and next_value:
            url = next_value
            idx += 2
            continue
        if token.startswith("http://") or token.startswith("https://"):
            url = token
        idx += 1

    data_match = re.search(r'(?:-d|--data|--data-raw|--data-binary|--data-urlencode)\s+"((?:\\.|[^"\\])*)"', command, re.DOTALL)
    if not data_match:
        data_match = re.search(r"(?:-d|--data|--data-raw|--data-binary|--data-urlencode)\s+'((?:\\.|[^'\\])*)'", command, re.DOTALL)
    if data_match:
        body_text = bytes(data_match.group(1), "utf-8").decode("unicode_escape")

    if not url:
        raise ValueError("The cURL command does not include a target URL.")
    if normalize_target_host(url) != normalize_target_host(target):
        raise ValueError("The cURL command target does not match the selected scan target host.")

    normalized = _normalize_request(
        method=method,
        url=url,
        headers=headers,
        cookies=cookies,
        body_text=body_text,
        request_name=name or urlparse(url).path or "Imported cURL",
        source_type="curl",
    )
    if not normalized:
        raise ValueError("Could not normalize the cURL command.")

    return {
        "name": name or "Imported cURL",
        "source_type": "curl",
        "requests": [normalized],
    }


def parse_openapi_content(content: bytes, target: str, filename: str = "Imported OpenAPI") -> Dict[str, Any]:
    target_host = normalize_target_host(target)
    try:
        payload = json.loads(content.decode("utf-8", errors="ignore"))
    except json.JSONDecodeError:
        try:
            payload = yaml.safe_load(content.decode("utf-8", errors="ignore"))
        except yaml.YAMLError:
            raise ValueError("Invalid OpenAPI file. Must be valid JSON or YAML.")

    if not isinstance(payload, dict):
        raise ValueError("Invalid OpenAPI file. Must be a JSON or YAML object.")

    paths = payload.get("paths", {})
    if not paths:
        raise ValueError("No paths found in OpenAPI specification.")

    requests: List[Dict[str, Any]] = []
    
    base_url = target
    if getattr(base_url, "endswith", None) and base_url.endswith("/"):
        base_url = base_url[:-1]

    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        
        for method, operation in methods.items():
            if method.lower() not in {"get", "post", "put", "delete", "patch", "options", "head"}:
                continue
            
            method_url = f"{base_url}{path}"
            headers: Dict[str, str] = {}
            cookies: Dict[str, str] = {}
            body_text = ""
            
            params = []
            if isinstance(operation, dict):
                parameters = operation.get("parameters", [])
                for param in parameters:
                    if param.get("in") == "query":
                        name = param.get("name")
                        if name:
                            params.append(f"{name}=1")
                    elif param.get("in") == "header":
                        name = param.get("name")
                        if name:
                            headers[name] = "dummy"
            
            if params:
                method_url += "?" + "&".join(params)
                
            if isinstance(operation, dict):
                req_body = operation.get("requestBody", {})
                content_map = req_body.get("content", {})
                if "application/json" in content_map:
                    headers["Content-Type"] = "application/json"
                    body_text = "{}"
                    
                    schema = content_map["application/json"].get("schema", {})
                    if schema.get("type") == "object" and "properties" in schema:
                        dummy_obj = {k: "dummy" for k in schema["properties"].keys()}
                        body_text = json.dumps(dummy_obj)
                
                elif "application/x-www-form-urlencoded" in content_map:
                    headers["Content-Type"] = "application/x-www-form-urlencoded"
                    schema = content_map["application/x-www-form-urlencoded"].get("schema", {})
                    if schema.get("type") == "object" and "properties" in schema:
                        dummy_params = {k: "dummy" for k in schema["properties"].keys()}
                        body_text = urlencode(dummy_params)

            normalized = _normalize_request(
                method=method.upper(),
                url=method_url,
                headers=headers,
                cookies=cookies,
                body_text=body_text,
                request_name=path or filename,
                source_type="openapi",
            )
            if normalized:
                requests.append(normalized)

    if not requests:
        raise ValueError("No valid HTTP requests could be generated from the OpenAPI file.")

    return {
        "name": filename.rsplit(".", 1)[0] or "Imported OpenAPI",
        "source_type": "openapi",
        "requests": requests,
    }
