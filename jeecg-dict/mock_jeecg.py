#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""本地 JeecgBoot 字典接口靶机（仅绑 127.0.0.1，自测用，全部数据为假）。

路由：
  GET /_app.config.js                      -> VITE_GLOB_API_URL / VITE_GLOB_APP_TITLE
  GET /api/sys/tenant/list                 -> 默认 404；--tenant 时返回 result=[{"id":"1"}]
  GET /api/sys/dict/getDictItems/<dictCode>
      - 原路径（无 .js）                    -> 401（模拟 Shiro）
      - 以 .js 结尾（且不是 .js/）          -> 404（模拟 nginx）
      - 以 .js/ 结尾                        -> 剥掉尾段执行 sqlite 求值
      - --waf 时任何字典接口请求            -> 403
"""
import argparse
import json
import re
import sqlite3
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DICT_PREFIX = "/api/sys/dict/getDictItems/"
FAIL_BODY = json.dumps(
    {"success": False, "message": "操作失败", "code": 500, "result": None,
     "timestamp": 1761696000000},
    ensure_ascii=False, separators=(",", ":")).encode("utf-8")  # 正好 93 字节


def _identifier(s):
    return re.fullmatch(r"[A-Za-z0-9_$]+", s or "") is not None


def _quote(s):
    return '"' + s.replace('"', '""') + '"'


class MockDB:
    def __init__(self, empty=False):
        self.db = sqlite3.connect(":memory:", check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        self.empty = empty
        if not empty:
            self._seed()

    def _seed(self):
        db = self.db
        db.executescript("""
        CREATE TABLE sys_dict (id TEXT, dict_name TEXT, dict_code TEXT);
        CREATE TABLE sys_user (id TEXT, realname TEXT, email TEXT, phone TEXT,
                               status TEXT, post TEXT);
        CREATE TABLE biz_address_book (id TEXT, full_name TEXT, identity TEXT,
                                       email TEXT, phone TEXT);
        CREATE TABLE onl_cgform_head (id TEXT, table_name TEXT);
        CREATE TABLE onl_cgform_field (id TEXT, cgform_head_id TEXT,
                                       db_field_name TEXT, db_type TEXT,
                                       db_field_txt TEXT);
        """)
        # 布尔差分用：真条件有行、假条件 0 行
        for i, (n, c) in enumerate([("性别", "1"), ("学历", "2"), ("民族", "3")], 1):
            db.execute("INSERT INTO sys_dict VALUES (?,?,?)", (str(i), n, c))
        # 系统用户：realname/email/phone 含空串，专门验证「返回行数 != 有值条数」
        db.executemany("INSERT INTO sys_user VALUES (?,?,?,?,?,?)", [
            ("1", "张三", "zhangsan@example.edu.cn", "13800138000", "1", "管理员"),
            ("2", "李四", "lisi@example.edu.cn", "", "1", ""),
            ("3", "", "", "13900139000", "0", ""),
            ("4", "王五", "", "", "1", "教师"),
        ])
        # 通讯录：全部空串（行数 >0，但有值条数 =0）
        db.executemany("INSERT INTO biz_address_book VALUES (?,?,?,?,?)", [
            ("1", "", "", "", ""),
            ("2", "", "", "", ""),
            ("3", "", "", "", ""),
        ])
        tables = ["sys_user", "biz_address_book", "onl_cgform_field", "onl_cgform_head",
                  "sys_dict", "biz_contact", "biz_summer_camp", "biz_attraction",
                  "biz_banner", "biz_calendar", "biz_checklist", "biz_checklist_record",
                  "biz_content", "biz_notice", "biz_schedule", "biz_teacher",
                  "biz_student", "biz_course", "biz_department"]
        for t in tables:
            db.execute("INSERT INTO onl_cgform_head VALUES (?,?)", (t, t))
        fields = [
            ("1", "sys_user", "realname", "string", "姓名"),
            ("2", "sys_user", "email", "string", "邮箱"),
            ("3", "sys_user", "phone", "string", "手机号"),
            ("4", "sys_user", "status", "string", "状态"),
            ("5", "sys_user", "post", "string", "职务"),
            ("6", "biz_address_book", "full_name", "string", "全名"),
            ("7", "biz_address_book", "identity", "string", "身份"),
            ("8", "biz_address_book", "email", "string", "邮箱"),
            ("9", "biz_address_book", "phone", "string", "联系电话"),
        ]
        db.executemany("INSERT INTO onl_cgform_field VALUES (?,?,?,?,?)", fields)
        db.commit()

    def table_exists(self, table):
        if self.empty:
            return False
        r = self.db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,))
        return r.fetchone() is not None

    def columns(self, table):
        r = self.db.execute(f"PRAGMA table_info({_quote(table)})")
        return [row["name"] for row in r.fetchall()]

    def query(self, table, text, code, flt):
        """返回 (ok, rows_or_msg)。只支持白名单简单条件。"""
        with self.lock:
            if self.empty or not self.table_exists(table):
                return False, "操作失败"
            if not (_identifier(table) and _identifier(text) and _identifier(code)):
                return False, "操作失败"
            cols = self.columns(table)
            if text not in cols or code not in cols:
                return False, "操作失败"
            cond = "1=1"
            if flt:
                f = flt.strip()
                m = re.fullmatch(r"1\s*=\s*1", f, re.I)
                if m:
                    cond = "1=1"
                else:
                    m = re.fullmatch(r"1\s*=\s*2", f, re.I)
                    if m:
                        cond = "1=2"
                    else:
                        m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\s+is\s+(not\s+)?null", f, re.I)
                        if m:
                            col = m.group(1)
                            neg = "not " if m.group(2) else ""
                            cond = f"{_quote(col)} is {neg}null"
                        else:
                            m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*'([^']*)'", f, re.I)
                            if m:
                                col = m.group(1)
                                val = m.group(2)
                                cond = f"{_quote(col)} = '{val}'"
                            else:
                                return False, "操作失败"
            sql = (f"SELECT {_quote(code)} AS value, {_quote(text)} AS text, "
                   f"{_quote(text)} AS label, {_quote(text)} AS title "
                   f"FROM {_quote(table)} WHERE {cond}")
            try:
                rows = [dict(r) for r in self.db.execute(sql).fetchall()]
            except sqlite3.Error:
                return False, "操作失败"
            return True, rows


class Handler(BaseHTTPRequestHandler):
    server_version = "MockJeecg/1.0"

    def log_message(self, fmt, *args):  # 安静一点
        pass

    def _send(self, code, body, ctype="application/json;charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _fail(self):
        self._send(200, FAIL_BODY)

    def do_GET(self):
        path = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)
        if path == "/_app.config.js":
            body = ('window.__CONF__={"VITE_GLOB_API_URL":"/api",'
                    '"VITE_GLOB_APP_TITLE":"测试站"};')
            self._send(200, body, "application/javascript;charset=utf-8")
            return
        if path == "/api/sys/tenant/list":
            if self.server.tenant:
                self._send(200, '{"success":true,"result":[{"id":"1"}]}')
            else:
                self._send(404, '{"success":false,"message":"Not Found"}')
            return
        if path.startswith(DICT_PREFIX):
            self._handle_dict(path)
            return
        self._send(404, '{"success":false,"message":"Not Found"}')

    def _handle_dict(self, path):
        if self.server.waf:
            self._send(403, "<html><body>Forbidden by WAF</body></html>", "text/html;charset=utf-8")
            return
        rest = path[len(DICT_PREFIX):]
        if rest.endswith(".js") and not rest.endswith(".js/"):
            self._send(404, "<html><head><title>404 Not Found</title></head></html>",
                       "text/html;charset=utf-8")
            return
        if not rest.endswith(".js/"):
            # 原路径：模拟 Shiro 未放行
            self._send(401, '{"success":false,"message":"Token失效，请重新登录!","code":401}')
            return
        core = rest[:-len(".js/")]
        dictcode = core.split("--", 1)[0].strip()
        parts = dictcode.split(",")
        if len(parts) < 3:
            self._fail()
            return
        table = parts[0].strip()
        text = parts[1].strip()
        code = parts[2].strip()
        flt = parts[3].strip() if len(parts) >= 4 else ""
        ok, rows = self.server.mdb.query(table, text, code, flt)
        if not ok:
            self._fail()
            return
        body = json.dumps({"success": True, "message": "", "code": 200, "result": rows},
                          ensure_ascii=False, separators=(",", ":"))
        self._send(200, body)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=18080)
    ap.add_argument("--empty", action="store_true")
    ap.add_argument("--waf", action="store_true")
    ap.add_argument("--tenant", action="store_true")
    args = ap.parse_args()

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.mdb = MockDB(empty=args.empty)
    server.waf = args.waf
    server.tenant = args.tenant
    print(f"MOCK READY 127.0.0.1:{args.port} empty={args.empty} waf={args.waf} tenant={args.tenant}",
          flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
