import re

def normalize_path(path: str) -> str:
    """ডাইনামিক প্যারামিটারগুলোকে ({id}, ${userId}, /123) স্ট্যান্ডার্ড ফরম্যাটে আনে।"""
    norm = re.sub(r'\$\{[^}]+\}|\{[^}]+\}', '{param}', path)
    norm = re.sub(r'/\d+(?=/|$)', '/{param}', norm)
    return norm.rstrip("/") or "/"

def detect_api_versions(paths: list[str]) -> set[str]:
    versions = set()
    for p in paths:
        match = re.search(r'/(v\d+)(?:/|$)', p, re.IGNORECASE)
        if match:
            versions.add(match.group(1).lower())
    return versions

def analyze_drift(js_endpoints: list[dict], spec_endpoints: list[dict] = None) -> list[dict]:
    findings = []
    sensitive_keywords = ("internal", "admin", "debug", "export", "secret", "config", "graphql", "private", "token", "billing", "payment")

    if not spec_endpoints:
        for item in js_endpoints:
            ep = item["endpoint"]
            params = item.get("params", "")
            is_sensitive = any(kw in ep.lower() for kw in sensitive_keywords) or bool(params)
            findings.append({
                "target": item.get("target", ""),
                "status": "[bold magenta]SENSITIVE API[/bold magenta]" if is_sensitive else "[bold cyan]DISCOVERED[/bold cyan]",
                "method": colorize_method(item["method"]),
                "endpoint": f"{ep}[bold yellow]{params}[/bold yellow]",
                "source": item["source"],
                "risk": "[bold red]HIGH (P1/P2)[/bold red]" if is_sensitive else "[green]INFO[/green]"
            })
        return findings

    spec_norm_map = {}
    spec_raw_paths = []
    for s in spec_endpoints:
        norm_p = normalize_path(s["endpoint"])
        spec_raw_paths.append(s["endpoint"])
        spec_norm_map.setdefault(norm_p, set()).add(s["method"].upper())

    spec_versions = detect_api_versions(spec_raw_paths)
    highest_spec_ver = max([int(v[1:]) for v in spec_versions], default=0)

    for item in js_endpoints:
        raw_ep = item["endpoint"]
        norm_ep = normalize_path(raw_ep)
        method = item["method"].upper()
        source = item["source"]
        params = item.get("params", "")
        target = item.get("target", "")

        # ১. Zombie API চেক
        ver_match = re.search(r'/v(\d+)(?:/|$)', raw_ep, re.IGNORECASE)
        if ver_match and highest_spec_ver > 0:
            js_ver = int(ver_match.group(1))
            if js_ver < highest_spec_ver and norm_ep not in spec_norm_map:
                findings.append({
                    "target": target,
                    "status": "[bold yellow]ZOMBIE API[/bold yellow]",
                    "method": colorize_method(method),
                    "endpoint": f"{raw_ep}[bold yellow]{params}[/bold yellow]",
                    "source": source,
                    "risk": "[bold red]HIGH (P1/P2)[/bold red]"
                })
                continue

        # ২. Shadow API চেক
        if norm_ep not in spec_norm_map:
            findings.append({
                "target": target,
                "status": "[bold red]SHADOW API[/bold red]",
                "method": colorize_method(method),
                "endpoint": f"{raw_ep}[bold yellow]{params}[/bold yellow]",
                "source": source,
                "risk": "[bold red]HIGH (P1/P2)[/bold red]"
            })
            continue

        # ৩. Method Drift চেক
        allowed_methods = spec_norm_map[norm_ep]
        if method not in allowed_methods:
            findings.append({
                "target": target,
                "status": "[bold orange1]METHOD DRIFT[/bold orange1]",
                "method": colorize_method(method),
                "endpoint": f"{raw_ep} [dim](Spec: {','.join(allowed_methods)})[/dim]",
                "source": source,
                "risk": "[bold yellow]MEDIUM (P2)[/bold yellow]"
            })

    return findings

def colorize_method(method: str) -> str:
    colors = {
        "GET": "green",
        "POST": "yellow",
        "PUT": "blue",
        "PATCH": "cyan",
        "DELETE": "bold red",
        "OPTIONS": "dim white"
    }
    color = colors.get(method.upper(), "white")
    return f"[{color}]{method.upper()}[/{color}]"
