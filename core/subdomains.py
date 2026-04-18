import os, re, shutil, socket, subprocess, requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from core.context import Context
from core.config import check_tool

CRT_RE = re.compile(r'([A-Za-z0-9_*.-]+\.[A-Za-z]{2,})')

def _dedup(items):
    out, seen = [], set()
    for item in items:
        if item and item not in seen:
            seen.add(item); out.append(item)
    return out

def _in_scope(host: str, domain: str) -> bool:
    host   = host.lower().strip().lstrip('*.')
    domain = domain.lower().strip()
    return host == domain or host.endswith('.' + domain)

def parse_robots_simple(raw):
    paths = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.lower().startswith(('disallow:', 'allow:')):
            p = line.split(':', 1)[1].strip()
            if p and p != '/' and '*' not in p:
                paths.append(p)
    return list(set(paths))

# ── Passive sources ───────────────────────────────────────────────────────────────────────

def passive_crtsh(domain, timeout, ua):
    hosts = []
    try:
        r = requests.get(
            f'https://crt.sh/?q=%25.{domain}&output=json',
            timeout=timeout, headers={'User-Agent': ua},
        )
        if r.status_code == 200 and r.text.strip():
            for row in r.json():
                for field in ('name_value', 'common_name'):
                    value = row.get(field, '') or ''
                    for part in str(value).splitlines():
                        h = part.strip().lstrip('*.').lower()
                        if _in_scope(h, domain):
                            hosts.append(h)
    except Exception:
        pass
    return _dedup(hosts)


def passive_urlscan(domain, timeout, ua):
    hosts = []
    try:
        r = requests.get(
            f'https://urlscan.io/api/v1/search/?q=domain:{domain}&size=200',
            timeout=timeout, headers={'User-Agent': ua},
        )
        if r.status_code == 200:
            for item in r.json().get('results', []):
                for key in ('page', 'task'):
                    obj = item.get(key, {}) or {}
                    h = (obj.get('domain') or obj.get('apexDomain') or '').strip().lower()
                    if _in_scope(h, domain):
                        hosts.append(h)
    except Exception:
        pass
    return _dedup(hosts)


def passive_wayback(domain, timeout, ua):
    hosts = []
    try:
        r = requests.get(
            'https://web.archive.org/cdx/search/cdx',
            params={'url': f'*.{domain}/*', 'output': 'text', 'fl': 'original',
                    'collapse': 'urlkey', 'limit': '2000'},
            timeout=timeout, headers={'User-Agent': ua},
        )
        if r.status_code == 200:
            for line in r.text.splitlines():
                line = line.strip()
                if not line.startswith('http'):
                    continue
                try:
                    h = (urlparse(line).hostname or '').lower()
                    if _in_scope(h, domain):
                        hosts.append(h)
                except Exception:
                    pass
    except Exception:
        pass
    return _dedup(hosts)


def passive_otx(domain, timeout, ua):
    hosts = []
    try:
        r = requests.get(
            f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns',
            timeout=timeout, headers={'User-Agent': ua},
        )
        if r.status_code == 200:
            for entry in r.json().get('passive_dns', []):
                h = (entry.get('hostname') or '').strip().lower()
                if _in_scope(h, domain):
                    hosts.append(h)
    except Exception:
        pass
    return _dedup(hosts)


def passive_rapiddns(domain, timeout, ua):
    hosts = []
    try:
        r = requests.get(
            f'https://rapiddns.io/subdomain/{domain}?full=1',
            timeout=timeout, headers={'User-Agent': ua},
        )
        if r.status_code == 200:
            for h in re.findall(r'([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')', r.text):
                h = h.strip().lower()
                if _in_scope(h, domain):
                    hosts.append(h)
    except Exception:
        pass
    return _dedup(hosts)


def passive_hackertarget(domain, timeout, ua):
    hosts = []
    try:
        r = requests.get(
            f'https://api.hackertarget.com/hostsearch/?q={domain}',
            timeout=timeout, headers={'User-Agent': ua},
        )
        if r.status_code == 200:
            for line in r.text.splitlines():
                parts = line.split(',')
                if parts:
                    h = parts[0].strip().lower()
                    if _in_scope(h, domain):
                        hosts.append(h)
    except Exception:
        pass
    return _dedup(hosts)


def passive_anubis(domain, timeout, ua):
    hosts = []
    try:
        r = requests.get(
            f'https://jldc.me/anubis/subdomains/{domain}',
            timeout=timeout, headers={'User-Agent': ua},
        )
        if r.status_code == 200:
            for h in r.json():
                h = h.strip().lower()
                if _in_scope(h, domain):
                    hosts.append(h)
    except Exception:
        pass
    return _dedup(hosts)


def passive_from_url_pool(url_pool, domain):
    hosts = []
    for url in url_pool:
        try:
            h = (urlparse(url).hostname or '').lower()
            if _in_scope(h, domain):
                hosts.append(h)
        except Exception:
            pass
    return _dedup(hosts)


# ── Active probes ──────────────────────────────────────────────────────────────────────

def active_dns(host, timeout):
    try:
        socket.setdefaulttimeout(timeout)
        socket.getaddrinfo(host, None)
        return True
    except Exception:
        return False


def active_httpx(hosts, workspace, timeout):
    if not hosts or not shutil.which('httpx'):
        return []
    inp = os.path.join(workspace, 'subdomains_candidates.txt')
    out = os.path.join(workspace, 'subdomains_live.txt')
    open(inp, 'w').write('\n'.join(hosts))
    try:
        subprocess.run(
            ['httpx', '-l', inp, '-silent', '-follow-host-redirects',
             '-title', '-tech-detect', '-status-code', '-o', out],
            capture_output=True, text=True, timeout=max(120, timeout * 4)
        )
        if os.path.exists(out):
            return [s.strip() for s in open(out).read().splitlines() if s.strip()]
    except Exception:
        pass
    return []


# ── Phase runner ───────────────────────────────────────────────────────────────────────

def run(ctx: Context, phase_num=2, total=10) -> Context:
    domain = getattr(ctx, 'target', '').strip()
    ctx.log(f'[subdomains] Enumerating subdomains for {domain}...')

    passive      = []
    source_counts = {}

    # subfinder (tool-based)
    if check_tool('subfinder', ctx.config):
        out_file = os.path.join(ctx.workspace, 'subdomains_subfinder.txt')
        try:
            subprocess.run(['subfinder', '-d', domain, '-silent', '-all', '-o', out_file],
                           capture_output=True, timeout=180)
        except Exception:
            pass
        sf_hosts = ([s.strip().lower() for s in open(out_file).read().splitlines() if s.strip()]
                    if os.path.exists(out_file) else [])
        passive.extend([h for h in sf_hosts if _in_scope(h, domain)])
        source_counts['subfinder'] = len(sf_hosts)
    else:
        source_counts['subfinder'] = 0

    # amass passive
    if check_tool('amass', ctx.config):
        out_file = os.path.join(ctx.workspace, 'subdomains_amass.txt')
        try:
            subprocess.run(['amass', 'enum', '-passive', '-d', domain, '-o', out_file,
                            '-timeout', '3'],
                           capture_output=True, timeout=240)
        except Exception:
            pass
        amass_hosts = ([s.strip().lower() for s in open(out_file).read().splitlines() if s.strip()]
                       if os.path.exists(out_file) else [])
        passive.extend([h for h in amass_hosts if _in_scope(h, domain)])
        source_counts['amass'] = len(amass_hosts)
    else:
        source_counts['amass'] = 0

    # All pure-HTTP passive sources in parallel
    ua = ctx.user_agent
    http_sources = {
        'crtsh':        (passive_crtsh,        [domain, ctx.timeout, ua]),
        'urlscan':      (passive_urlscan,       [domain, ctx.timeout, ua]),
        'wayback':      (passive_wayback,       [domain, ctx.timeout, ua]),
        'otx':          (passive_otx,           [domain, ctx.timeout, ua]),
        'rapiddns':     (passive_rapiddns,      [domain, ctx.timeout, ua]),
        'hackertarget': (passive_hackertarget,  [domain, ctx.timeout, ua]),
        'anubis':       (passive_anubis,        [domain, ctx.timeout, ua]),
    }

    with ThreadPoolExecutor(max_workers=len(http_sources)) as ex:
        futures = {ex.submit(fn, *args): name for name, (fn, args) in http_sources.items()}
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                hosts = fut.result() or []
                passive.extend(hosts)
                source_counts[name] = len(hosts)
                ctx.log(f'[subdomains]   {name:<14} → {len(hosts)} hosts')
            except Exception as e:
                source_counts[name] = 0
                ctx.log(f'[subdomains]   {name:<14} → error: {e}')

    # URL pool
    pool_hosts = passive_from_url_pool(ctx.url_pool, domain)
    passive.extend(pool_hosts)
    source_counts['url_pool'] = len(pool_hosts)

    passive = _dedup([h for h in passive if _in_scope(h, domain)])
    ctx.log(f'[subdomains] Total passive candidates: {len(passive)}')

    # Active step 1: DNS
    dns_live = []
    workers  = min(100, max(1, len(passive)))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(active_dns, h, ctx.timeout): h for h in passive}
        for fut in as_completed(futures):
            h = futures[fut]
            try:
                if fut.result():
                    dns_live.append(h)
            except Exception:
                pass
    dns_live = _dedup(dns_live)
    ctx.log(f'[subdomains] DNS live: {len(dns_live)}')

    # Active step 2: HTTP probe
    httpx_live = (active_httpx(dns_live, ctx.workspace, ctx.timeout)
                  if check_tool('httpx', ctx.config) else [])

    ctx.subdomains      = dns_live
    ctx.subdomains_live = httpx_live

    # Robots enrichment on live web hosts
    for sub in (httpx_live or dns_live)[:50]:
        sub_url  = sub if sub.startswith('http') else f'https://{sub}'
        host_key = sub.replace('https://', '').replace('http://', '').split('/')[0]
        try:
            r = requests.get(urljoin(sub_url, '/robots.txt'),
                             timeout=ctx.timeout,
                             headers={'User-Agent': ctx.user_agent})
            if r.status_code == 200 and len(r.text) > 10:
                paths = parse_robots_simple(r.text)
                ctx.subdomain_robots[host_key] = paths
                for p in paths:
                    ctx.robots_paths.append(p)
                    ctx.url_pool.append(urljoin(sub_url, p))
        except Exception:
            pass

    ctx.write_json('subdomains_sources.json', source_counts)
    ctx.write_text('subdomains_all.txt',      '\n'.join(passive))
    ctx.write_text('subdomains_dns_live.txt', '\n'.join(dns_live))
    ctx.write_text('subdomains.txt',          '\n'.join(httpx_live or dns_live))
    ctx.phases_run.append('subdomains')
    ctx.log_phase_done(phase_num, total, 'subdomains',
        f"passive={len(passive)} | dns_live={len(dns_live)} | "
        f"web_live={len(httpx_live)} | robots={len(ctx.subdomain_robots)}")
    return ctx
