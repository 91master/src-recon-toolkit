#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""离线重出报告：用已落盘的 00-scan.json + 目录里的图重建 docx（默认不再打目标）。

用法：
  python3 rebuild_report.py <hits目录>                    # 只重排文字，图沿用现值
  python3 rebuild_report.py <hits目录> --refetch            # 重新取打码样例并重画图 2（约 10 个请求）
  python3 rebuild_report.py <hits目录> --refetch --out x.docx
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import judge  # noqa: E402
import probe  # noqa: E402
import report  # noqa: E402


def refetch_samples(rec, max_fields=20, per_field=5):
    """只取 PII 列的样例，就地打码；明文不出这个函数。"""
    p = probe.Probe(rec["host"], delay=0.15, max_requests=max_fields + 4)
    prefix = rec.get("prefix") or "/api"
    samples = {}
    for f in (rec.get("pii_fields") or [])[:max_fields]:
        res = p.dict_rows(prefix, f["table"], f["col"], "id", f"{f['col']} is not null")
        if not res or not res.get("values"):
            continue
        vals = [v for v in res["values"] if str(v or "").strip()][:per_field]
        if vals:
            samples[f"{f['table']}.{f['col']}"] = [report.mask(f["col"], v) for v in vals]
    return samples


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("hitdir")
    ap.add_argument("--out", default=None)
    ap.add_argument("--refetch", action="store_true", help="重新取样例并重画两张图")
    a = ap.parse_args()

    scan = os.path.join(a.hitdir, "00-scan.json")
    rec = json.load(open(scan, encoding="utf-8"))
    verdict = judge.judge(rec)
    imgs = {"stats": os.path.join(a.hitdir, "11-字段统计.png"),
            "samples": os.path.join(a.hitdir, "12-脱敏样例.png")}

    if a.refetch:
        import datetime
        rec["ts"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " CST"   # 图注时间要用本次取样时刻
        samples = refetch_samples(rec)
        rec["samples"] = samples
        json.dump(rec, open(scan, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        rendered = report.render_images(rec, samples, a.hitdir)
        imgs = rendered if isinstance(rendered, dict) else {"stats": rendered[0], "samples": rendered[1]}
        print("样例条数：", {k: len(v) for k, v in samples.items()})
    else:
        samples = rec.get("samples") or {"kept": []}
        if not all(os.path.exists(v) for v in imgs.values()):
            raise SystemExit("缺图，且没给 --refetch：图不在了就没法只重排文字")

    out = a.out or os.path.join(a.hitdir, "report.docx")
    report.build_docx(rec, verdict, samples, a.hitdir, out, imgs)
    print("重建完成：", out)
    print("判读：", verdict["verdict"], verdict["level"])


if __name__ == "__main__":
    main()
