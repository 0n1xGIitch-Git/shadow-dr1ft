import re
import asyncio
import httpx
from urllib.parse import urljoin, urlparse
from rich.console import Console

console = Console()

ENDPOINT_REGEX = re.compile(
    r"""(?:"|'|`)((?:https?://[a-zA-Z0-9\.\-]+(?:/api|/v[0-9]+|/graphql)[a-zA-Z0-9_\-\./\{\}\$\?=&]*)|(?:/api|/v[0-9]+|/graphql|/gql|/internal|/admin|/auth|/rest|/backend|/oauth|/sso|/webhook|/rpc|/service|/services|/user|/users|/account|/billing|/payment|/projects|/branches|/endpoints)[a-zA-Z0-9_\-\./\{\}\$\?=&]*)(?:"|'|`)""",
    re.IGNORECASE
)

CHUNK_REGEX = re.compile(
    r"""(?:"|'|`)([a-zA-Z0-9_\-\./]+(?:chunk|bundle|main|app|vendor|manifest|routes|index|assets)[a-zA-Z0-9_\-\.]*\.js)(?:"|'|`)""",
    re.IGNORECASE
)

PARAM_REGEX = re.compile(
    r"""\b(is_?admin|role|privilege|user_?id|account_?id|org_?id|tenant_?id|debug|internal|token|api_?key|secret|permissions?)\b\s*:""",
    re.IGNORECASE
)

AXIOS_METHOD_REGEX = re.compile(
    r"""\.(get|post|put|delete|patch|options)\s*\(\s*(?:"|'|`)((?:/api|/v[0-9]+|/graphql|/internal|/admin|/auth|/rest|/backend|/user|/users|/projects)[a-zA-Z0-9_\-\./\{\}\$\?=&]*)(?:"|'|`)""",
    re.IGNORECASE
)

FETCH_METHOD_REGEX = re.compile(
    r"""fetch\s*\(\s*(?:"|'|`)((?:/api|/v[0-9]+|/graphql|/internal|/admin|/auth|/rest|/backend|/user|/users|/projects)[a-zA-Z0-9_\-\./\{\}\$\?=&]*)(?:"|'|`)\s*,\s*\{[^\}]{0,150}?method\s*:\s*(?:"|'|`)(GET|POST|PUT|DELETE|PATCH|OPTIONS)(?:"|'|`)""",
    re.IGNORECASE | re.DOTALL
)

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5"
}

def _scan_js_content(content: str, source_name: str, seen: set, extracted: list[dict], target_url: str = ""):
    method_map = {}

    for match in AXIOS_METHOD_REGEX.finditer(content):
        method, path = match.group(1).upper(), match.group(2)
        method_map[path.split("?")[0]] = method

    for match in FETCH_METHOD_REGEX.finditer(content):
        path, method = match.group(1), match.group(2).upper()
        method_map[path.split("?")[0]] = method

    found_params = sorted(set(m.group(1) for m in PARAM_REGEX.finditer(content)))
    param_hint = f" [Params: {','.join(found_params[:3])}]" if found_params else ""

    for match in ENDPOINT_REGEX.finditer(content):
        raw_path = match.group(1)
        clean_path = raw_path.split("?")[0]

        if clean_path.startswith(("http://", "https://")):
            parsed = urlparse(clean_path)
            clean_path = parsed.path

        if len(clean_path) < 4 or clean_path.endswith((".js", ".css", ".png", ".jpg", ".svg", ".woff", ".ico", ".map", ".html")):
            continue

        method = method_map.get(clean_path, "GET")
        key = (target_url, method, clean_path)

        if key not in seen:
            seen.add(key)
            extracted.append({
                "target": target_url,
                "method": method,
                "endpoint": clean_path,
                "params": param_hint,
                "raw_params": found_params[:5],
                "source": source_name
            })

async def _fetch_text(client: httpx.AsyncClient, url: str, semaphore: asyncio.Semaphore) -> tuple[str, str, str]:
    """(final_url, response_text, error_reason) রিটার্ন করে।"""
    async with semaphore:
        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                return str(resp.url), resp.text, ""
            return str(resp.url), "", f"HTTP {resp.status_code}"
        except httpx.ConnectError:
            return url, "", "DNS Resolution / Connection Failed (Host unreachable)"
        except httpx.TimeoutException:
            return url, "", "Request Timeout"
        except Exception as e:
            return url, "", str(e)

async def deep_crawl_target(target_url: str, headers: dict = None, concurrency: int = 20) -> list[dict]:
    req_headers = {**DEFAULT_HEADERS, **(headers or {})}
    semaphore = asyncio.Semaphore(concurrency)
    extracted = []
    seen = set()

    async with httpx.AsyncClient(timeout=20.0, follow_redirects=True, verify=False, headers=req_headers) as client:
        final_url, html, err = await _fetch_text(client, target_url, semaphore)
        if not html:
            console.print(f"[bold yellow][!] Skipped {target_url} -> {err}[/bold yellow]")
            return extracted

        inline_matches = re.findall(r'<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>', html, re.IGNORECASE | re.DOTALL)
        for idx, code in enumerate(inline_matches, 1):
            if code.strip():
                _scan_js_content(code, f"inline-{idx}", seen, extracted, target_url)

        js_urls = set()
        for src in re.findall(r'(?:src|href)=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', html, re.IGNORECASE):
            js_urls.add(urljoin(final_url, src))

        tasks = [_fetch_text(client, j_url, semaphore) for j_url in js_urls]
        js_results = await asyncio.gather(*tasks)

        discovered_chunks = set()
        valid_js_count = 0
        for j_url, content, _ in js_results:
            if not content:
                continue
            valid_js_count += 1
            filename = urlparse(j_url).path.split("/")[-1] or "bundle.js"
            _scan_js_content(content, filename, seen, extracted, target_url)

            for chunk in CHUNK_REGEX.findall(content):
                chunk_url = urljoin(j_url, chunk)
                if chunk_url not in js_urls:
                    discovered_chunks.add(chunk_url)

        if discovered_chunks:
            chunk_tasks = [_fetch_text(client, c_url, semaphore) for c_url in list(discovered_chunks)[:60]]
            chunk_results = await asyncio.gather(*chunk_tasks)
            for c_url, c_content, _ in chunk_results:
                if c_content:
                    valid_js_count += 1
                    c_name = urlparse(c_url).path.split("/")[-1] or "chunk.js"
                    _scan_js_content(c_content, f"{c_name} (chunk)", seen, extracted, target_url)

        console.print(f"[dim][*] Scanned {valid_js_count} JS/Chunk files & {len(inline_matches)} inline scripts on {target_url}[/dim]")

    return extracted

async def scan_multiple_targets(target_urls: list[str], headers: dict = None, concurrency: int = 20) -> list[dict]:
    all_extracted = []
    target_sem = asyncio.Semaphore(5)

    async def _bounded_crawl(u: str):
        async with target_sem:
            return await deep_crawl_target(u, headers, concurrency)

    results = await asyncio.gather(*[_bounded_crawl(u) for u in target_urls])
    for res in results:
        all_extracted.extend(res)
    return all_extracted
