import subprocess, os, requests
from urllib.parse import urljoin
from core.context import Context
from core.config import check_tool

def parse_robots_simple(raw):
    paths = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith(("disallow:","allow:")):
            p = line.split(":",1)[1].strip()
            if p and p != "/" and "*" not in p:
                paths.append(p)
    return list(set(paths))

def run(ctx: Context, phase_num=2, total=10) -> Context:
    ctx.log(f"[subdomains] Enumerating subdomains for {ctx.target}...")

    if not check_tool("subfinder", ctx.config):
        ctx.log(f"[subdomains] subfinder not found — skipping")
        ctx.phases_run.append("subdomains")
        ctx.log_phase_done(phase_num, total, "subdomains", "subfinder not installed — skipped")
        return ctx

    out_file = os.path.join(ctx.workspace, "subdomains_raw.txt")
    try:
        subprocess.run(
            ["subfinder","-d",ctx.target,"-silent","-o",out_file],
            capture_output=True, timeout=120
        )
    except Exception as e:
        ctx.log(f"[subdomains] subfinder failed: {e}")

    raw_subs = open(out_file).read().splitlines() if os.path.exists(out_file) else []
    ctx.log(f"[subdomains] {len(raw_subs)} subdomains raw")

    live_subs = raw_subs
    if check_tool("httpx", ctx.config):
        live_file = os.path.join(ctx.workspace, "subdomains_live.txt")
        try:
            open(os.path.join(ctx.workspace,"subs_tmp.txt"),"w").write("\n".join(raw_subs))
            subprocess.run(
                f"cat {ctx.workspace}/subs_tmp.txt | httpx -silent -o {live_file}",
                shell=True, capture_output=True, timeout=120
            )
            if os.path.exists(live_file):
                live_subs = [s.strip() for s in open(live_file).read().splitlines() if s.strip()]
        except:
            pass

    ctx.subdomains = live_subs

    for sub in live_subs[:20]:
        sub_url = f"https://{sub}" if not sub.startswith("http") else sub
        try:
            r = requests.get(urljoin(sub_url,"/robots.txt"),
                             timeout=ctx.timeout, headers={"User-Agent": ctx.user_agent})
            if r.status_code == 200 and len(r.text) > 10:
                paths = parse_robots_simple(r.text)
                ctx.subdomain_robots[sub] = paths
                for p in paths:
                    ctx.robots_paths.append(p)
                    ctx.url_pool.append(urljoin(sub_url, p))
        except:
            pass

    ctx.write_text("subdomains.txt", "\n".join(ctx.subdomains))
    ctx.phases_run.append("subdomains")
    ctx.log_phase_done(phase_num, total, "subdomains",
        f"{len(live_subs)} live subdomains ({len(ctx.subdomain_robots)} with robots.txt)")
    return ctx
