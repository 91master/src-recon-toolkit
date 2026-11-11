#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
js_to_endpoints.py —— 给一个站点，扒前端 JS 出接口清单，再逐条测"未登录能不能调"。

用法：
    python3 js_to_endpoints.py https://example.edu.cn
    python3 js_to_endpoints.py https://example.edu.cn --proxy http://127.0.0.1:8080 --delay 0.5
    python3 js_to_endpoints.py https://x.edu.cn --cookie "PHPSESSID=abc" --out out.csv

产出：
    endpoints_<host>.csv    path, method, status, size, ctype, snippet
    终端打印：探到的接口数 / 未授权可调的清单

判据提醒（来自 2026-10-26 交战记录）：
  · 401/403 是挡得住的；200 但要带会话的，看返回里有没有 notLogin / 未登录 / errcode!=0
  · 200 且 body 里有真实业务字段 = 候选，要人工看
  · 500「缺少参数」往往等于"方法存在且把参数名告诉你了"（ASMX 判据）
"""
import argparse, csv, json, re, sys, time
from urllib.parse import urljoin, urlparse

import requests
import urllib3
urllib3.disable_warnings()

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36"

# 明显不是接口的东西
NOISE = re.compile(
    r"\.(?:css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|webp|bmp)(?:\?|$)|"
    r"(?:^|/)(?:node_modules|\.git)/|^/static/|^/assets/|^/images?/|^/fonts?/", re.I)

# 接口特征
PATTERNS = [
    # asmx / do / action / php 之类的方法式接口
    (re.compile(r'["\'`]([A-Za-z0-9_\-]+\.asmx/[A-Za-z0-9_]+)["\'`]'), "asmx"),
    # 常见前缀（api/app/jsonp/publicapp/rest/service 等）
    (re.compile(r'["\'`](/(?:api|app|apps|rest|service|jsonp|publicapp|open|v\d|prod-api|dev-api|sys|admin|portal|webservice)/[A-Za-z0-9_\-./{}$]{1,80})["\'`]'), "prefixed"),
    # pe("/xxx") / url: "/xxx" / fetch("/xxx") / axios.get("/xxx")
    (re.compile(r'(?:pe|url|fetch|axios\.(?:get|post)|\.open)\(\s*["\'`](/[A-Za-z0-9_\-./{}$]{2,80})["\'`]'), "call"),
    # 任意以 / 开头的路径串（兜底，靠 NOISE 过滤）
    (re.compile(r'["\'`](/[A-Za-z][A-Za-z0-9_\-./{}$]{2,80})["\'`]'), "generic"),
]


def get(sess, url, **kw):
    kw.setdefault("timeout", 20)
    kw.setdefault("verify", False)
    kw.setdefault("allow_redirects", False)
    return sess.get(url, **kw)


def fetch_html(sess, base):
    for p in ["/", "/index.html", "/main.html"]:
        try:
            r = get(sess, base + p)
            if r.status_code == 200 and len(r.content) > 300:
                return r.text, base + p
        except Exception:
            continue
    return "", None


def collect_js(sess, base, html, page_url, max_js=60):
    """返回 {js_url: text}"""
    srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
    srcs += re.findall(r'["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', html)
    out, seen = {}, set()
    for s in srcs:
        if s.startswith("data:"):
            continue
        u = urljoin(page_url or base + "/", s)
        if u in seen or urlparse(u).netloc != urlparse(base).netloc:
            continue
        seen.add(u)
        if len(out) >= max_js:
            break
        try:
            r = get(sess, u)
            if r.status_code == 200 and len(r.content) > 200:
                out[u] = r.text
        except Exception:
            pass
    return out


def extract(js_texts):
    eps = {}
    for u, t in js_texts.items():
        for rx, kind in PATTERNS:
            for m in rx.finditer(t):
                p = m.group(1)
                if NOISE.search(p):
                    continue
                if len(p) < 4 or len(p) > 90:
                    continue
                eps.setdefault(p, kind)
    return eps


def probe(sess, base, path, delay):
    """先 GET，再视情况 POST 空 JSON。返回 (method, status, size, ctype, snippet)"""
    url = base + path if path.startswith("/") else base + "/" + path
    results = []
    try:
        r = get(sess, url)
        results.append(("GET", r.status_code, len(r.content), r.headers.get("Content-Type", ""), r))
    except Exception as e:
        results.append(("GET", "ERR:%s" % type(e).__name__, 0, "", None))
    time.sleep(delay)

    # GET 404/405 时试 POST 空 JSON（ASMX / Spring 常见）
    if results[-1][1] in (404, 405, "ERR:ConnectionError"):
        try:
            r = sess.post(url, data="{}", timeout=20, verify=False, allow_redirects=False,
                          headers={"Content-Type": "application/json"})
            results.append(("POST", r.status_code, len(r.content), r.headers.get("Content-Type", ""), r))
        except Exception as e:
            results.append(("POST", "ERR:%s" % type(e).__name__, 0, "", None))
        time.sleep(delay)

    best = max(results, key=lambda x: (x[1] == 200, x[2] if isinstance(x[1], int) else 0))
    m, st, ln, ct, resp = best
    snip = ""
    if resp is not None:
        snip = re.sub(r"\s+", " ", resp.text[:160])
    return m, st, ln, ct, snip


def classify(st, ln, ct, snip):
    """返回 (tag, 说明)。tag: SHELL/LOGIN/DATA/EMPTY/ERR/-"""
    if not isinstance(st, int):
        return "ERR", ""
    low = snip.lower()
    if st in (401, 403):
        return "LOGIN", "挡得住"
    if st != 200:
        return "-", ""
    # SPA 外壳：text/html + 以 <!DOCTYPE 开头
    if "text/html" in ct.lower() and low.lstrip().startswith("<!doctype"):
        return "SHELL", "前端壳，不是接口"
    if re.search(r"(notlogin|未登录|未登陆|请先登录|token失效|验证信息为空)", low):
        return "LOGIN", "逻辑层要会话"
    if "json" in ct.lower():
        if re.search(r'"(errcode|code)"\s*:\s*"?0"?', low) and '"data"' in low:
            if re.search(r'"data"\s*:\s*(null|\[\]|""|\{\})', low):
                return "EMPTY", "通但没数据"
            return "DATA", "★ 有数据，人工看"
        if re.search(r'"(errcode|code)"\s*:\s*"?[1-9]', low):
            return "LOGIN", "业务层拒绝"
        return "DATA", "★ 有返回，人工看"
    if ln > 200:
        return "DATA", "★ 非 JSON 但有内容，人工看"
    return "EMPTY", ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("base", help="站点根，如 https://x.edu.cn")
    ap.add_argument("--proxy", default=None)
    ap.add_argument("--cookie", default=None)
    ap.add_argument("--delay", type=float, default=0.4)
    ap.add_argument("--out", default=None)
    ap.add_argument("--max-js", type=int, default=60)
    ap.add_argument("--no-probe", action="store_true", help="只出清单不探测")
    a = ap.parse_args()

    base = a.base.rstrip("/")
    if not base.startswith("http"):
        base = "https://" + base
    host = urlparse(base).netloc

    sess = requests.Session()
    sess.verify = False
    sess.headers.update({"User-Agent": UA})
    if a.proxy:
        sess.proxies = {"http": a.proxy, "https": a.proxy}
    if a.cookie:
        sess.headers["Cookie"] = a.cookie

    print("[*] 目标 %s" % base)
    html, page_url = fetch_html(sess, base)
    if not html:
        print("[!] 首页取不到（可能整站跳登录/网关）。仍尝试常见 JS 目录。")
    js = collect_js(sess, base, html, page_url, a.max_js)
    print("[*] JS %d 个，共 %.1f KB" % (len(js), sum(len(t) for t in js.values()) / 1024))

    eps = extract(js)
    print("[*] 接口候选 %d 条" % len(eps))
    if not eps:
        return

    rows = []
    if a.no_probe:
        for p, k in sorted(eps.items()):
            rows.append((p, k, "", "", "", ""))
    else:
        for i, (p, k) in enumerate(sorted(eps.items()), 1):
            m, st, ln, ct, snip = probe(sess, base, p, a.delay)
            tag, why = classify(st, ln, ct, snip)
            print("  %-46s %-5s %-8s %7sB %-18s %-6s %s"
                  % (p[:46], m, st, ln, ct.split(";")[0][:18], tag, why))
            rows.append((p, m, st, ln, ct, tag, snip))

    out = a.out or ("endpoints_%s.csv" % host.replace(":", "_"))
    with open(out, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["path", "method", "status", "size", "content_type", "tag", "snippet"])
        w.writerows(rows)
    print("\n[*] 写入 %s（%d 行）" % (out, len(rows)))
    from collections import Counter
    print("[*] 分布：%s" % dict(Counter((r[5] if len(r) > 5 else "") for r in rows)))
    hits = [r for r in rows if len(r) > 5 and r[5] == "DATA"]
    if hits:
        print("\n[*] ★ 需要人工看的 %d 条：" % len(hits))
        for r in hits:
            print("    %-44s %7sB  %s" % (r[0][:44], r[3], r[6][:100]))


if __name__ == "__main__":
    main()
