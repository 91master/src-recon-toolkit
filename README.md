# src-recon-toolkit

两个自用的小工具，用来把「前端扒接口」和「JeecgBoot 字典接口判读」这两件重复的事做成可复现的命令，
而不是每次手敲 curl。

- `js-recon/` —— 从一个站点扒前端 JS / 真跑页面抓 XHR，产出接口清单，并逐条测「不登录能不能调」
- `jeecg-dict/` —— JeecgBoot 字典接口未授权 SQL 注入的探测 → 判读 → 取证（脱敏）→ Word 报告流水线

两件都只发 GET、只读、带请求预算。

> 这些工具只在下述前提下有意义：**你对该资产有明确的书面授权（SRC / 众测 / 客户委托 / 自己的靶场）**。
> 代码里没有内置任何真实目标，示例一律 `example.edu.cn` 与 `127.0.0.1`。

## 安装

```bash
python3 -m pip install -r requirements.txt
python3 -m playwright install chromium      # 只有 capture_xhr.py 需要
```

## js-recon

### `js_to_endpoints.py` —— 扒 JS 出接口，再测未授权

```bash
python3 js-recon/js_to_endpoints.py https://example.edu.cn --delay 0.5
python3 js-recon/js_to_endpoints.py https://example.edu.cn --cookie "SESSION=xxx" --out out.csv
```

产出 `endpoints_<host>.csv`：`path, method, status, size, ctype, snippet`。

判读口径（写进脚本注释里了）：

| 现象 | 含义 |
|---|---|
| 401 / 403 | 挡得住 |
| 200 但 body 里有 `notLogin` / `未登录` / `errcode != 0` | 前端跳转，服务端仍拒 |
| 200 且 body 有真实业务字段 | 候选，必须人工看 |
| 500「缺少参数」 | 方法存在，而且把参数名告诉你了 |

### `capture_xhr.py` —— 让页面自己跑一遍，抓它发出的 XHR

静态扒 JS 只能拿到路径，拿不到请求体；Vue/Angular 的检索接口参数是运行时拼的。

```bash
python3 js-recon/capture_xhr.py "https://opac.example.edu.cn/search_adv.php"
python3 js-recon/capture_xhr.py "https://example.edu.cn" --wait 8000 --click "#searchBtn"
```

产出 `xhr_<host>.jsonl`，每条带 `method url status size ctype post_data`，可直接重放。

### `js_api_extract.py` —— 批量：页面 + 应用级 JS → 接口与参数名

跳过 jquery/vue/axios/layui 这类公共库，只留应用代码。

```bash
python3 js-recon/js_api_extract.py https://example.edu.cn -o out.json
python3 js-recon/js_api_extract.py urls.txt -o out.json     # 一行一个 URL
HTTP_PROXY=http://127.0.0.1:8080 python3 js-recon/js_api_extract.py https://example.edu.cn
```

## jeecg-dict

把「JeecgBoot 字典接口未授权 SQL 注入」的手工链路固化成一条命令：
输入目标池 → 自动探测 → 自动判读分级 → 自动出证据（脱敏）+ Word 报告 → `triage.csv` + `SUMMARY.md`。

```bash
cd jeecg-dict
# 1) 自测：起本地 mock（只绑 127.0.0.1），跑完整流水线并断言 4 个反例场景
python3 pipeline.py --self-test

# 2) 目标池
python3 pipeline.py --targets targets/sample_pool.csv \
    --out out/run-001 --concurrency 4 --delay 0.15 --max-requests 80

# 3) 单台
python3 pipeline.py --host http://127.0.0.1:18080 --out out/demo
```

细节（判据表、状态文件语义、请求预算、报告结构）见 [`jeecg-dict/README.md`](jeecg-dict/README.md)。

设计上刻意写死的几条，别放宽：

- 阶段固定，任何一步判负即早退，不继续烧请求；
- 每台有 `--max-requests` 上限与 `--delay` 限速，预算账本随报告输出；
- 「返回行数」与「有值条数」分开记，空串不算有值；
- PII 样例只取 ≤5 条并打码，只统计不落值；
- 分级偏保守：有 PII 且有数据 → 中危；有数据无 PII → 低危；只有绕过 → 判负，不往高危推。

## 目录

```
js-recon/       js_to_endpoints.py  capture_xhr.py  js_api_extract.py
jeecg-dict/     pipeline.py  probe.py  judge.py  report.py  mock_jeecg.py  test_units.py  run_tests.sh
```

## 自测

```bash
cd jeecg-dict && ./run_tests.sh      # 语法 → 单元 → mock 端到端 → 报告体检
```

## License

MIT，见 `LICENSE`。
