#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""单元测试：不打网络，只测判读规则与打码规则（run_tests.sh 会先跑这个）。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import judge  # noqa: E402
import report  # noqa: E402

CASES = []


def case(name):
    def deco(fn):
        CASES.append((name, fn))
        return fn
    return deco


def rec_base(**kw):
    rec = {
        "host": "https://demo.example.edu.cn",
        "prefix": "/api",
        "fingerprint": {"ok": True},
        "bypass": {"open": True, "waf": False, "raw": {"code": 401}, "js": {"code": 404},
                   "jsslash": {"code": 200, "size": 93}},
        "tenant": {"state": "http404"},
        "diff": {"injected": False},
        "fields": [],
    }
    rec.update(kw)
    return rec


# ---------------- 判读规则 ----------------
@case("有 PII 且条数>0 → 可交/中危")
def _():
    r = rec_base(diff={"injected": True},
                 fields=[{"table": "sys_user", "col": "realname", "label": "姓名",
                          "pii": True, "rows": 259, "nonempty": 259}])
    v = judge.judge(r)
    assert v["verdict"] == "可交", v
    assert v["level"] == "中危", v
    assert r["pii_rows"] == 259, r["pii_rows"]


@case("注入成立但只有业务数据 → 可交/低危")
def _():
    r = rec_base(diff={"injected": True},
                 fields=[{"table": "biz_calendar", "col": "address", "label": "",
                          "pii": False, "rows": 55, "nonempty": 53}])
    v = judge.judge(r)
    assert v["verdict"] == "可交", v
    assert v["level"] == "低危", v


@case("注入成立但读不到数据 → 可交/低危（空库或表名不符）")
def _():
    r = rec_base(diff={"injected": True},
                 fields=[{"table": "sys_user", "col": "realname", "pii": True,
                          "rows": 0, "nonempty": 0}])
    v = judge.judge(r)
    assert v["verdict"] == "可交" and v["level"] == "低危", v


@case("多租户开着且没出数 → 判负-多租户")
def _():
    r = rec_base(tenant={"state": "on", "n": 2})
    v = judge.judge(r)
    assert v["verdict"] == "判负-多租户", v


@case("放行但差分不成立 → 判负-仅绕过")
def _():
    v = judge.judge(rec_base())
    assert v["verdict"] == "判负-仅绕过", v


@case("403 由 WAF 返回 → 判负-WAF")
def _():
    r = rec_base(bypass={"open": False, "waf": True})
    v = judge.judge(r)
    assert v["verdict"] == "判负-WAF", v


@case("拿不到 API 前缀 → 判负-非 JeecgBoot")
def _():
    r = rec_base(fingerprint={"ok": False}, bypass={"open": False, "waf": False})
    v = judge.judge(r)
    assert v["verdict"] == "判负-非 JeecgBoot", v


@case("summarize 能把可交按等级排出来")
def _():
    r1 = rec_base(diff={"injected": True},
                  fields=[{"table": "sys_user", "col": "phone", "label": "手机号",
                           "pii": True, "rows": 23, "nonempty": 23}])
    r2 = rec_base(tenant={"state": "on"})
    r1["pii_rows"] = 23
    txt = judge.summarize([(r1, judge.judge(r1)), (r2, judge.judge(r2))])
    assert "可交" in txt and "中危" in txt, txt


# ---------------- 打码规则 ----------------
@case("手机号留前 3 后 4")
def _():
    assert report.mask("phone", "13812345678") == "138****5678"
    assert report.mask("mobile", "138-1234-5678") == "138****5678"


@case("短号/分机留首尾，不整段星号")
def _():
    out = report.mask("telephone", "8888")
    assert out[0] == "8" and out[-1] == "8" and "*" in out, out


@case("邮箱留首字母与域名")
def _():
    assert report.mask("email", "zhangsan@example.edu.cn") == "z***@example.edu.cn"


@case("姓名留首尾各 1 字，两字姓名只留首字")
def _():
    assert report.mask("realname", "张三丰") == "张*丰"
    assert report.mask("realname", "张三") == "张*"


@case("身份证留前 4 后 2")
def _():
    out = report.mask("idcard", "330106199001011234")
    assert out.startswith("3301") and out.endswith("34") and "*" in out, out


@case("分类字段不打码（Teacher 不能被遮成 T*****r）")
def _():
    assert report.mask("identity", "Teacher") == "Teacher"
    assert report.mask("status", "启用") == "启用"


@case("空值不打码成星号")
def _():
    assert report.mask("realname", "") == ""
    assert report.mask("phone", None) == ""


def main():
    ok = fail = 0
    for name, fn in CASES:
        try:
            fn()
            print(f"  PASS  {name}")
            ok += 1
        except AssertionError as e:
            print(f"  FAIL  {name}  →  {e}")
            fail += 1
        except Exception as e:
            print(f"  ERR   {name}  →  {type(e).__name__}: {e}")
            fail += 1
    print(f"UNIT: {ok}/{ok+fail} PASS")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
