#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""js_api_extract.py —— 无表单页面的接口提取：抓页面 + 应用级 JS，抽出接口路径与参数名。

跳过公共库（jquery/bootstrap/vue/axios/layui/element/chosen…），只留应用代码。
只发 GET 拿静态资源，不调用任何业务接口。

用法：
    python3 js_api_extract.py https://example.edu.cn
    python3 js_api_extract.py urls.txt -o out.json          # 一行一个 URL
    HTTP_PROXY=http://127.0.0.1:8080 python3 js_api_extract.py https://example.edu.cn

产出：JSON，{url: {js, fetched, endpoints:{path:[参数名]}, params:[...]}}
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from urllib.parse import urljoin, urlsplit

PROXY = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy") or ""
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36"

LIB = re.compile(r'(jquery|bootstrap|vue(\.min)?|react|axios|layui|element|chosen|swiper|echarts|'
                 r'popper|modernizr|html5shiv|respond|font-?awesome|moment|dayjs|lodash|underscore|'
                 r'polyfill|babel|wow|animate|owl|slick|require(\.min)?\.js|sea\.js|router\.min)', re.I)
EP = re.compile(r'["\'`](/?[A-Za-z0-9_\-/\.]{2,80}?\.(?:do|action|json|ashx|aspx|asp|php|jsp|htm|html))'
                r'(?:\?([^"\'`]{0,120}))?["\'`]', re.I)
PARAM = re.compile(r'(?:params|data|query)\s*[:=]\s*\{([^}]{0,300})\}', re.S)


def fetch(url):
    tmp = tempfile.NamedTemporaryFile(delete=False).name
    cmd = ['curl', '-sS', '-k', '-L', '--max-redirs', '3', '-m', '15', '--compressed',
           '-A', UA, '-o', tmp, '-w', '%{http_code}|%{size_download}|%{url_effective}']
    if PROXY:
        cmd += ['-x', PROXY]
    cmd.append(url)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
        code, size, eff = (r.stdout.split('|') + ['', '', ''])[:3]
        raw = open(tmp, 'rb').read(400000)
        return code, size, eff, raw.decode('utf-8', 'replace')
    except Exception:
        return 'ERR', '0', url, ''
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def extract(html, base):
    host = urlsplit(base).netloc
    srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)', html, re.I)
    js = [s for s in srcs if not LIB.search(s)]
    eps, params = {}, set()

    def scan(txt):
        for m in EP.finditer(txt):
            p = m.group(1)
            qs = m.group(2) or ''
            if p.startswith('//'):
                p = '/' + p[2:].split('/', 1)[-1]
            eps.setdefault(p, set())
            for kv in qs.split('&'):
                if '=' in kv:
                    eps[p].add(kv.split('=')[0].strip())
        for m in PARAM.finditer(txt):
            for k in re.findall(r'["\']?([A-Za-z_][A-Za-z0-9_]{1,24})["\']?\s*:', m.group(1)):
                params.add(k)

    scan(html)
    inline = re.findall(r'<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>', html, re.S)
    for s in inline:
        scan(s)
    got = 0
    for s in js[:10]:
        u = urljoin(base, s)
        if urlsplit(u).netloc != host and not s.startswith('/'):
            continue
        code, size, eff, body = fetch(u)
        got += 1
        if code == '200':
            scan(body)
        time.sleep(0.3)
    return dict(js=len(js), fetched=got,
                endpoints={k: sorted(v) for k, v in eps.items() if len(k) > 4},
                params=sorted(params)[:40])


def main():
    ap = argparse.ArgumentParser(description="从页面与应用 JS 里抽取接口路径与参数名（只发 GET 取静态资源）")
    ap.add_argument("target", help="URL，或一行一个 URL 的文本文件")
    ap.add_argument("-o", "--out", default="js_api_extract.json")
    ap.add_argument("--limit", type=int, default=0, help="最多处理几条（0=全部）")
    a = ap.parse_args()

    if os.path.isfile(a.target):
        urls = [l.strip() for l in open(a.target, encoding="utf-8") if l.strip()
                and not l.strip().startswith("#")]
    else:
        urls = [a.target]
    if a.limit:
        urls = urls[:a.limit]
    print("目标", len(urls), flush=True)

    out = {}
    for i, u in enumerate(urls, 1):
        code, size, eff, html = fetch(u)
        if code != '200':
            out[u] = dict(code=code, endpoints={}, params=[])
            print('%-3d %-6s %s' % (i, code, u[:66]), flush=True)
            continue
        d = extract(html, eff or u)
        out[u] = d
        print('%-3d JS=%-3d 取=%-3d 接口=%-3d %s' % (i, d['js'], d['fetched'], len(d['endpoints']), u[:56]), flush=True)
        for k in list(d['endpoints'])[:4]:
            print('      ', k[:70], d['endpoints'][k][:5], flush=True)
        time.sleep(0.5)

    with open(a.out, 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print('→', a.out, flush=True)


if __name__ == '__main__':
    main()
