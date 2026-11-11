"""判读层：把探测结果折成「结论 + 建议等级 + 下一步」，规则全部可追溯。"""

PII_COLS = {
    "realname": "姓名", "full_name": "全名", "name": "名称", "username": "登录名",
    "phone": "手机号", "mobile": "手机号", "telephone": "电话", "email": "邮箱",
    "idcard": "身份证", "id_card": "身份证", "sfzh": "身份证", "address": "地址",
    "identity": "身份", "id_number": "证件号", "stu_no": "学号", "work_no": "工号",
    "student_no": "学号", "user_no": "工号", "counsellor": "辅导员", "counselor": "辅导员",
    "lender": "借出人", "borrower": "借用人", "avatar": "头像", "log_content": "操作内容",
}
# 判「可交」的门槛：命中口径 = 有真实个人信息，或能证明可读业务数据
BIG_PII = 500   # 个人信息条数达到这个量级仍按中危（不往高危推：无凭据、无写权限）


import re as _re

_FALLBACK = [
    (_re.compile(r"(^|_)contact($|_)|phone|mobile|tel($|_)|telephone", _re.I), "联系方式"),
    (_re.compile(r"email|mail", _re.I), "邮箱"),
    (_re.compile(r"(stu|student|work|user|counsel+or|teacher|staff)_no$", _re.I), "工号/学号"),
    (_re.compile(r"(^|_)ip$|_ip$", _re.I), "来源IP"),
]


def classify_field(col):
    """先查表，再按列名形态兜底（lender_contact、counsellor_no 这类不在表里的）。"""
    c = (col or "").lower()
    if c in PII_COLS:
        return PII_COLS[c]
    for pat, label in _FALLBACK:
        if pat.search(c):
            return label
    return None


def judge(rec):
    """rec: dict with fingerprint/bypass/tenant/diff/fields/tables"""
    fp = rec.get("fingerprint") or {}
    bp = rec.get("bypass") or {}
    tn = rec.get("tenant") or {}
    df = rec.get("diff") or {}
    fields = rec.get("fields") or []

    pii = [f for f in fields if f.get("pii") and (f.get("nonempty") or 0) > 0]
    biz = [f for f in fields if not f.get("pii") and (f.get("nonempty") or 0) > 0]
    pii_rows = sum(f.get("nonempty") or 0 for f in pii)
    data_fields = [f for f in fields if (f.get("nonempty") or 0) > 0]

    rec["pii_fields"] = pii
    rec["biz_fields"] = biz
    rec["pii_rows"] = pii_rows

    if not fp.get("ok"):
        return dict(verdict="判负-非 JeecgBoot", level="-", reason="取不到 API 前缀", next="换目标")

    if df.get("injected"):
        if pii:
            kind = "、".join(sorted({classify_field(f["col"]) for f in pii}))
            # 证件号属敏感个人信息：千条以上直接按高危，不再压在「中危」档
            ids = [f for f in pii if (classify_field(f["col"]) or "") in ("身份证", "证件号")]
            id_rows = sum(f.get("nonempty") or 0 for f in ids)
            if id_rows >= 1000:
                level = "高危"
                reason = f"未授权可读身份证号 {id_rows} 条（敏感个人信息，达千条级）"
            else:
                level = "中危"
                reason = f"未授权可读个人信息（{kind}，字段级有值 {pii_rows} 条，人数以逐表行数为准）"
            nxt = "出报告 → 人工核一遍复验数字 → 提交"
        elif data_fields:
            level = "低危"
            reason = "未授权可读数据，但字段不是个人信息"
            nxt = "看业务表是否还有敏感列（人工补测）"
        else:
            level = "低危"
            reason = "注入成立但读不到数据（空库/表名对不上）"
            nxt = "换表名或换实例"
        return dict(verdict="可交", level=level, reason=reason, next=nxt)

    if tn.get("state") == "on":
        return dict(verdict="判负-多租户", level="-", reason="tenant/list 匿名可读、SQL 被强制加 tenant_id",
                    next="跳过，别在 dict 上耗")
    if bp.get("open"):
        return dict(verdict="判负-仅绕过", level="-",
                    reason=".js/ 放行但布尔差分不成立（白名单版/空库/表名不符）",
                    next="查 _app.config 版本，3.9.5+ 视为已修")
    if bp.get("waf"):
        return dict(verdict="判负-WAF", level="-", reason="403 由边缘 WAF 返回", next="换目标；同一 WAF 池别再刷")
    return dict(verdict="判负-未绕过", level="-", reason=".js/ 仍 401/404", next="记录，14 天内不重扫")


def summarize(rows):
    """rows: list of (rec, verdict_dict) → 一屏总览文本"""
    from collections import Counter
    c = Counter(v["verdict"] for _, v in rows)
    hit = [(r, v) for r, v in rows if v["verdict"] == "可交"]
    lines = [f"目标 {len(rows)} 台：" + " · ".join(f"{k} {n}" for k, n in c.most_common())]
    if hit:
        lines.append("")
        lines.append("可交（按等级排序）：")
        for r, v in sorted(hit, key=lambda x: (x[1]["level"] != "中危", x[0]["host"])):
            pii = f"｜PII {r['pii_rows']} 条" if r["pii_rows"] else ""
            lines.append(f"  [{v['level']}] {r['host']}{pii}｜{v['reason']}")
    else:
        lines.append("本轮 0 台可交。")
    return "\n".join(lines)
