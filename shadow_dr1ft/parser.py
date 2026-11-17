import json
import yaml
import httpx
from pathlib import Path
from rich.console import Console

console = Console()

def load_openapi_spec(spec_source: str, headers: dict = None) -> list[dict]:
    """লোকাল ফাইল অথবা রিমোট URL থেকে OpenAPI/Swagger স্পেসিফিকেশন লোড করে।"""
    raw_content = ""
    
    try:
        # যদি URL দেওয়া হয়
        if spec_source.startswith(("http://", "https://")):
            with httpx.Client(timeout=15.0, follow_redirects=True, verify=False) as client:
                resp = client.get(spec_source, headers=headers or {"User-Agent": "shadow-dr1ft/1.0"})
                resp.raise_for_status()
                raw_content = resp.text
        # যদি লোকাল ফাইল পাথ দেওয়া হয়
        else:
            file_path = Path(spec_source)
            if not file_path.exists():
                console.print(f"[bold red][!] Spec file not found:[/bold red] {spec_source}")
                return []
            raw_content = file_path.read_text(encoding="utf-8")

        # JSON বা YAML পার্স করা
        try:
            spec_data = json.loads(raw_content)
        except json.JSONDecodeError:
            spec_data = yaml.safe_load(raw_content)

        return extract_paths_from_spec(spec_data)

    except Exception as e:
        console.print(f"[bold red][!] Failed to parse OpenAPI spec:[/bold red] {e}")
        return []

def extract_paths_from_spec(spec_data: dict) -> list[dict]:
    """পার্স করা স্পেসিফিকেশন থেকে সব অফিশিয়াল এন্ডপয়েন্ট ও মেথড বের করে।"""
    documented_endpoints = []
    
    if not isinstance(spec_data, dict):
        return documented_endpoints

    # Swagger 2.0-এর ক্ষেত্রে basePath থাকতে পারে (যেমন: /api/v1)
    base_path = spec_data.get("basePath", "").rstrip("/")
    paths = spec_data.get("paths", {})

    valid_methods = {"get", "post", "put", "delete", "patch", "options", "head"}

    for path, methods_obj in paths.items():
        if not isinstance(methods_obj, dict):
            continue
            
        full_path = f"{base_path}{path}" if not path.startswith(base_path) else path
        
        for method in methods_obj.keys():
            if method.lower() in valid_methods:
                documented_endpoints.append({
                    "method": method.upper(),
                    "endpoint": full_path
                })

    return documented_endpoints
