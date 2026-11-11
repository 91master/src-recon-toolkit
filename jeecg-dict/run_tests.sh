#!/bin/bash
# jeecg_autopilot 一键自测：语法 → 单元 → mock 端到端 → 报告体检
# 只用 127.0.0.1，不碰任何真实目标
set -u
cd "$(dirname "$0")" || exit 1
PY=/usr/bin/python3
FAIL=0
step() { printf "\n[%d/4] %s\n" "$1" "$2"; }

step 1 "语法检查 py_compile"
if $PY -m py_compile probe.py judge.py report.py pipeline.py mock_jeecg.py rebuild_report.py test_units.py; then
  echo "  OK"
else
  echo "  FAIL"; FAIL=1
fi

step 2 "单元测试（判读规则 + 打码规则，不打网络）"
if $PY test_units.py; then :; else FAIL=1; fi

step 3 "mock 端到端（5 个场景：可交 / 多租户 / 空库 / WAF）"
if $PY pipeline.py --self-test; then :; else FAIL=1; fi

step 4 "报告体检（对最近一次 demo 产物：图/表/段落）"
DOCX=$(ls -t ../out/jeecg-autopilot/demo/hits/*/report.docx 2>/dev/null | head -1)
if [ -z "${DOCX:-}" ]; then
  DOCX=$(ls -t ../../out/jeecg-autopilot/*/hits/*/report.docx 2>/dev/null | head -1)
fi
if [ -n "${DOCX:-}" ] && [ -f "$DOCX" ]; then
  $PY - "$DOCX" <<'EOF' || FAIL=1
import sys, docx
d = docx.Document(sys.argv[1])
print(f"  图 {len(d.inline_shapes)} 张，表 {len(d.tables)} 个，段 {len(d.paragraphs)} 段")
assert len(d.inline_shapes) >= 2, "报告缺图"
EOF
else
  echo "  跳过：还没跑过端到端（先跑 pipeline.py --host http://127.0.0.1:<port> --out out/jeecg-autopilot/demo）"
fi

echo
if [ "$FAIL" -eq 0 ]; then
  echo "RESULT: 全部通过"
else
  echo "RESULT: 有失败项，见上"
fi
exit "$FAIL"
