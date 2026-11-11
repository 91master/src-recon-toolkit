#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
capture_xhr.py —— 让页面在无头浏览器里真跑一遍，抓它自己发出的 XHR/fetch。

为什么需要它：
    静态扒 JS 只能拿到"路径"，拿不到"请求体长什么样"。
    Angular/Vue 的检索接口（如汇文 ajax_search_adv.php、ehall 的 /queryXxx）
    参数结构是运行时构造的，只有让页面自己跑一遍才能抄到。

用法：
    python3 capture_xhr.py "https://opac.example.edu.cn/opac/search_adv.php"
    python3 capture_xhr.py "https://x.edu.cn" --wait 8000 --click "#searchBtn"
    python3 capture_xhr.py "https://example.edu.cn" --proxy http://127.0.0.1:8080

产出：
    xhr_<host>.jsonl  每条：method url status size ctype post_data（可直接拿去重放）

注意：
    · 默认无头 Chromium；页面卡住/白屏时加 --wait 或 --headed
    · 只读：只截流，不改包
"""
import argparse, json, re, sys, time
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

SKIP = re.compile(r"\.(?:css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|webp|mp4)(?:\?|$)", re.I)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--wait", type=int, default=6000, help="页面加载后再等多久（毫秒）")
    ap.add_argument("--out", default=None)
    ap.add_argument("--proxy", default=None)
    ap.add_argument("--headed", action="store_true")
    ap.add_argument("--click", default=None, help="加载后点一下这个选择器（触发检索）")
    ap.add_argument("--fill", action="append", default=[],
                    help='填表单，格式 "选择器=值"，可多次（如 --fill ".searchWord=计算机"）')
    ap.add_argument("--press", default=None, help="在指定选择器上按回车（常用于触发检索）")
    ap.add_argument("--timeout", type=int, default=45000)
    a = ap.parse_args()

    host = urlparse(a.url).netloc
    out = a.out or ("xhr_%s.jsonl" % host.replace(":", "_"))
    hits = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=not a.headed,
                                    proxy={"server": a.proxy} if a.proxy else None)
        ctx = browser.new_context(user_agent=UA, ignore_https_errors=True,
                                  viewport={"width": 1366, "height": 900})
        page = ctx.new_page()

        def on_response(resp):
            try:
                req = resp.request
                if req.resource_type not in ("xhr", "fetch"):
                    return
                if SKIP.search(resp.url):
                    return
                body = ""
                try:
                    body = resp.text()[:1500]
                except Exception:
                    pass
                hits.append({
                    "method": req.method,
                    "url": resp.url,
                    "status": resp.status,
                    "ctype": (resp.headers or {}).get("content-type", ""),
                    "post_data": (req.post_data or "")[:2000],
                    "req_headers": {k: v for k, v in (req.headers or {}).items()
                                    if k.lower() in ("content-type", "authorization", "x-requested-with",
                                                     "referer", "cookie", "uitoken", "x-sign", "x-timestamp")},
                    "resp_head": body,
                })
            except Exception:
                pass

        page.on("response", on_response)
        print("[*] 打开 %s" % a.url)
        try:
            page.goto(a.url, wait_until="domcontentloaded", timeout=a.timeout)
        except Exception as e:
            print("[!] goto 失败：%s（仍继续等待已触发的请求）" % e)
        page.wait_for_timeout(a.wait)

        for f in a.fill:
            try:
                sel, _, val = f.partition("=")
                page.fill(sel, val, timeout=8000)
                print("[*] 填入 %s = %s" % (sel, val))
            except Exception as e:
                print("[!] 填充失败 %s：%s" % (f, e))

        if a.press:
            try:
                page.press(a.press, "Enter", timeout=8000)
                print("[*] 在 %s 上回车" % a.press)
                page.wait_for_timeout(5000)
            except Exception as e:
                print("[!] 回车失败：%s" % e)

        if a.click:
            try:
                page.click(a.click, timeout=8000)
                print("[*] 已点击 %s" % a.click)
                page.wait_for_timeout(4000)
            except Exception as e:
                print("[!] 点击失败：%s" % e)

        title = ""
        try:
            title = page.title()
        except Exception:
            pass
        browser.close()

    print("[*] 页面标题：%s" % (title or "(空)"))
    print("[*] 捕获 XHR/fetch %d 条" % len(hits))

    # 去重（同 url+body 只留一条）
    seen, uniq = set(), []
    for h in hits:
        k = (h["method"], h["url"], h["post_data"][:200])
        if k in seen:
            continue
        seen.add(k)
        uniq.append(h)

    for h in uniq:
        print("  %-5s %-8s %6sB  %s" % (h["method"], h["status"],
                                        len(h["resp_head"]), h["url"][:96]))
        if h["post_data"]:
            print("         body: %s" % re.sub(r"\s+", " ", h["post_data"])[:220])
        if h["req_headers"]:
            print("         hdr : %s" % json.dumps(h["req_headers"], ensure_ascii=False)[:220])

    with open(out, "w", encoding="utf-8") as f:
        for h in uniq:
            f.write(json.dumps(h, ensure_ascii=False) + "\n")
    print("\n[*] 写入 %s（%d 条）" % (out, len(uniq)))
    print("[*] 重放提示：post_data 里就是可以直接拿去 curl 的请求体")


if __name__ == "__main__":
    main()
