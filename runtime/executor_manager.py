#!/usr/bin/env python3
"""Explicit local management and policy-gated delegation for registered executor routes."""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import json
import os
import re
from pathlib import Path
import secrets
import stat
import subprocess
import sys
from types import SimpleNamespace
import uuid
import webbrowser

import agent_jobs as jobs

HERE = Path(__file__).resolve().parent
ROOT = jobs.MANAGER
EFFORTS = ("low", "medium", "high", "xhigh")
ACTIONS = {"grant", "probe", "accept", "revoke"}


def hash_bytes(data):
    return hashlib.sha256(data).hexdigest()


def file_identity(p, *, directory=False):
    s = p.stat() if directory else p.lstat()
    if directory and not stat.S_ISDIR(s.st_mode) or not directory and not stat.S_ISREG(s.st_mode):
        raise ValueError("无法核对项目目录或文件身份")
    return [s.st_dev, s.st_ino] if directory else [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns]


def project(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 4096 or "\x00" in value:
        raise ValueError("请选择一个绝对项目目录")
    p = Path(value)
    if not p.is_absolute() or p == Path("/") or p == Path.home().resolve() or p.resolve(strict=True) != p:
        raise ValueError("须指定精确的真实项目目录，不能用磁盘根、用户根或符号链接")
    return str(p), file_identity(p, directory=True)


def route_fingerprint(route):
    return jobs.managed_fingerprint(route)


def discover():
    rows = []
    for route in sorted(jobs.route_specs()):
        try:
            route_fingerprint(route)
            detected = True
        except (OSError, ValueError, KeyError):
            detected = False
        rows.append(dict(id=route, name=route, kind="cli", detected=detected, effort="medium",
                         efforts=EFFORTS))
    return rows


class Manager:
    def __init__(self, root=ROOT):
        self.root = root

    @contextmanager
    def locked(self):
        jobs.verify_state()
        if self.root.resolve() != self.root:
            raise ValueError("管理目录不得含符号链接")
        jobs.secure_dir(self.root)
        n = os.open(self.root / "lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(n, "r+b") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            p = self.root / "grants.json"
            yield jobs.read(p) if p.exists() else {}

    def register(self, route, codex_home, codex_bin):
        with self.locked():
            spec = jobs.profile_spec(route, codex_home, codex_bin)
            routes = jobs.route_specs()
            if routes.get(route) != spec:
                routes[route] = spec
                jobs.atomic(self.root / "routes.json", jobs.encoded(routes))
        return {"route": route, "provider": "openai", "registered": True}

    def save(self, grants):
        jobs.atomic(self.root / "grants.json", jobs.encoded(grants))

    @staticmethod
    def binding_current(grant, route):
        try:
            return (not grant["revoked"]
                    and project(grant["cwd"])[1] == grant["projectIdentity"]
                    and route_fingerprint(route) == grant["fingerprint"])
        except (ValueError, OSError, KeyError, RuntimeError, subprocess.SubprocessError):
            return False

    def probe_status(self, record):
        safe = dict(id=record["id"], executionStatus="unknown", acceptanceStatus="pending")
        try:
            view = jobs.status(jobs.job_path(record["id"]))
        except (OSError, ValueError, KeyError):
            return safe
        if (view["route"], view.get("cwd"), view["model"], view["effort"], view.get("taskSha256")) != (
                record["route"], record["cwd"], record["model"], record["effort"], record["taskSha256"]):
            return safe
        return {k: view[k] for k in safe}

    def ready(self, route, grant):
        p = grant.get("probe")
        return bool(p and grant.get("confirmed") == p["id"] and self.binding_current(grant, route)
                    and self.probe_status(p) == {"id": p["id"], "executionStatus": "completed", "acceptanceStatus": "passed"}
                    and self.nonce_matches(p))

    @staticmethod
    def nonce_matches(record):
        try:
            result = jobs.collect(jobs.job_path(record["id"]))["result"]
            return bool(result and result.strip() == record["nonce"])
        except (OSError, ValueError, KeyError):
            return False

    def state(self):
        rows = discover()
        with self.locked() as grants:
            pool = []
            for row in rows:
                r = row["id"]
                g = grants.get(r)
                row["grant"] = None
                if not g:
                    continue
                current = self.binding_current(g, r)
                ready = self.ready(r, g) if current else False
                row["grant"] = {k: g[k] for k in ("revision", "cwd", "model", "effort", "revoked")}
                record = g.get("probe")
                probe = self.probe_status(record) if record else None
                if probe:
                    probe["replyMatches"] = probe["executionStatus"] == "completed" and self.nonce_matches(record)
                row["grant"].update(enabled=ready, bindingCurrent=current, probe=probe,
                                     managerConfirmed=bool(record and g.get("confirmed") == record["id"]))
                if ready:
                    pool.append(r)
            return {"routes": rows, "pool": pool}

    def pool(self, cwd, *, mcp_identity=None):
        with self.locked() as grants:
            p, identity = project(cwd)
            if mcp_identity is not None and mcp_identity != identity:
                raise ValueError("当前项目目录已更换，请重新初始化项目连接")
            return [{"route": r, "revision": g["revision"], "model": g["model"], "effort": g["effort"]}
                    for r, g in sorted(grants.items()) if g["cwd"] == p and self.ready(r, g)]

    def original(self, id, *, collect=False, mcp_project=None, mcp_identity=None):
        job = jobs.job_path(id)
        with self.locked():
            path = self.root / f"intent-{id}.json"
            if not path.is_file():
                raise ValueError("原 ID 不属于执行器管理器")
            intent = jobs.read(path)
            if mcp_project is not None:
                scope, identity = project(mcp_project)
                if (mcp_identity is not None and mcp_identity != identity
                        or intent.get("kind") != "mcp-delegate" or intent.get("project") != scope
                        or intent.get("projectIdentity") != identity or intent.get("id") != id):
                    raise ValueError("原 ID 不属于此项目的 MCP 派单")
            if not (job / "request.json").is_file():
                view = {"id": id, "route": intent["route"], "executionStatus": "unknown",
                        "acceptanceStatus": "pending", "nativeExecutionObserved": False}
                return {"job": view, "receipt": None, "result": None} if collect else view
            request = jobs.request_at(job)
            if request["route"] != intent["route"] or request.get("managed", {}).get("revision") != intent["revision"]:
                raise ValueError("原 ID 的托管授权绑定不匹配")
            if mcp_project is not None:
                managed = request["managed"]
                if (request.get("cwd") != scope or managed.get("project") != scope
                        or managed.get("projectIdentity") != identity or managed.get("cwdIdentity") != identity):
                    raise ValueError("原 ID 的项目目录绑定不匹配")
            return (jobs.collect if collect else jobs.status)(job)

    def call(self, action, args, *, mcp_identity=None):
        required = {"grant": {"cwd", "model", "effort"}, "probe": set(),
                    "revoke": set(), "accept": {"id"}, "delegate": {"cwd", "id", "task_file"},
                    "mcp-delegate": {"cwd", "id", "task_file"}}[action]
        if not isinstance(args, dict) or set(args) != {"route", "revision"} | required:
            raise ValueError("请求字段不符合操作")
        route = args["route"]
        if not isinstance(route, str) or not jobs.ROUTE_PATTERN.fullmatch(route):
            raise ValueError("执行器名称无效")
        with self.locked() as grants:
            if route not in jobs.route_specs():
                raise ValueError("请先注册此执行器")
            g = grants.get(route)
            if (g["revision"] if g else None) != args["revision"]:
                raise ValueError("授权版本已更新，请刷新页面或重新查询执行池")
            if action == "grant":
                cwd, identity = project(args["cwd"])
                model, effort = args["model"], args["effort"]
                if not isinstance(model, str) or not jobs.MODEL_PATTERN.fullmatch(model) or effort not in EFFORTS:
                    raise ValueError("模型 ID 或推理档位无效")
                revision = str(uuid.uuid4())
                g = dict(cwd=cwd, projectIdentity=identity, fingerprint=route_fingerprint(route),
                         model=model, effort=effort, revision=revision, revoked=False, probe=None)
                grants[route] = g
                self.save(grants)
                return {"ok": True, "revision": revision}
            if not g:
                raise ValueError("请先按项目授权")
            if action == "revoke":
                g.update(revoked=True, revision=str(uuid.uuid4()))
                self.save(grants)
                return {"ok": True}
            if not self.binding_current(g, route):
                raise ValueError("授权已撤回或执行器、账号、项目绑定变化")
            if action == "probe":
                if g.get("probe"):
                    return {"ok": True, **self.probe_status(g["probe"])}
                id = str(uuid.uuid4())
                nonce = "EXECUTOR-CHECK-" + secrets.token_hex(10)
                work = self.root / id
                work.mkdir(mode=0o700)
                empty = work / "workspace"
                empty.mkdir(mode=0o700)
                text = f"Reply with exactly {nonce}. Do not use tools, read files, or change anything.\n".encode()
                brief = work / "brief.txt"
                jobs.private(brief, text)
                g["probe"] = dict(id=id, nonce=nonce, route=route, cwd=str(empty), model=g["model"],
                                  effort=g["effort"], taskSha256=hash_bytes(text), revision=g["revision"])
                # Durable record before submit: interrupted submission stays on this ID.
                self.intent(id, route, g["revision"], "probe")
                self.save(grants)
                self.submit(id, route, g, str(empty), str(brief))
                return {"ok": True, **self.probe_status(g["probe"])}
            if action == "accept":
                p = g.get("probe")
                if not p or p["id"] != args["id"] or p["revision"] != g["revision"]:
                    raise ValueError("必须验收本授权版本的原探针 ID")
                view = self.probe_status(p)
                if view["executionStatus"] != "completed":
                    raise ValueError("原探针还没有已确认的执行结果")
                origin = jobs.job_path(p["id"])
                if not self.nonce_matches(p):
                    raise ValueError("原探针回复和预期口令不一致")
                if view["acceptanceStatus"] == "pending":
                    jobs.record_acceptance(origin, SimpleNamespace(verdict="passed",
                            reviewer="local-manager-operator", evidence="exact nonce manually confirmed; exact original ID"))
                elif view["acceptanceStatus"] != "passed":
                    raise ValueError("原探针验收未通过，不能启用")
                if self.probe_status(p)["acceptanceStatus"] != "passed":
                    raise ValueError("原探针验收未确认")
                g["confirmed"] = p["id"]
                self.save(grants)
                return {"ok": True}
            cwd, identity = project(args["cwd"])
            if (not self.ready(route, g) or cwd != g["cwd"] or identity != g["projectIdentity"]
                    or (action == "mcp-delegate" and identity != mcp_identity)):
                raise ValueError("当前项目没有这条已验收的委派授权")
            self.intent(args["id"], route, g["revision"], action,
                        scope=(g["cwd"], g["projectIdentity"]) if action == "mcp-delegate" else None)
            return self.submit(args["id"], route, g, g["cwd"], args["task_file"])

    def record_acceptance(self, args):
        self.original(args.id)
        with self.locked():
            intent = jobs.read(self.root / f"intent-{args.id}.json")
            if intent["kind"] == "probe":
                raise ValueError("Use the manager's Confirm button to accept a probe")
            return jobs.record_acceptance(jobs.job_path(args.id), args)

    def intent(self, id, route, revision, kind, *, scope=None):
        if jobs.job_path(id).exists():
            raise ValueError("原任务 ID 已存在，不可重新派发")
        path = self.root / f"intent-{id}.json"
        try:
            value = {"id": id, "route": route, "revision": revision, "kind": kind}
            if scope:
                value.update(project=scope[0], projectIdentity=scope[1])
            jobs.private(path, jobs.encoded(value))
            jobs.sync_dir(self.root)
        except FileExistsError:
            raise ValueError("此 ID 已登记，按原 ID 查单，不能重复派发") from None

    @staticmethod
    def submit(id, route, g, cwd, task_file):
        return jobs.submit(SimpleNamespace(id=id, route=route, cwd=cwd, task_file=task_file,
                            model=g["model"], effort=g["effort"], timeout=120,
                            managed={"revision": g["revision"], "fingerprint": g["fingerprint"],
                                     "project": g["cwd"], "projectIdentity": g["projectIdentity"],
                                     "cwdIdentity": file_identity(Path(cwd), directory=True)}))


def serve(manager, *, open_tab=True):
    token = secrets.token_urlsafe(32)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, code, body, kind="application/json; charset=utf-8"):
            if isinstance(body, dict):
                body = jobs.encoded(body)
            self.send_response(code)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy",
                 "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'self'")
            self.end_headers()
            self.wfile.write(body)

        def permitted(self, *, mutate=False):
            origin = self.headers.get_all("Origin") or []
            auth = self.headers.get_all("Authorization") or []
            return (self.headers.get_all("Host") == [host]
                    and (origin == [url] if mutate else origin in ([], [url]))
                    and len(auth) == 1 and hmac.compare_digest(auth[0].encode(), ("Bearer " + token).encode()))

        def do_GET(self):
            if self.headers.get_all("Host") != [host]:
                return self.reply(403, {"error": "无效的本地访问来源"})
            page = self.path.split("?", 1)[0]
            if page == "/api/state":
                if not self.permitted():
                    return self.reply(403, {"error": "请从本次初始化打开管理页"})
                try:
                    return self.reply(200, manager.state())
                except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                    return self.reply(503, {"error": "暂时无法读取本地执行器状态"})
            static = {"/": (HERE / "manager.html", "text/html"), "/executors": (HERE / "manager.html", "text/html"),
                      "/manager.js": (HERE / "manager.js", "text/javascript"),
                      "/manager.css": (HERE / "manager.css", "text/css")}
            if page not in static:
                return self.reply(404, {"error": "页面不存在"})
            path, mime = static[page]
            try:
                return self.reply(200, path.read_bytes(), mime + "; charset=utf-8")
            except OSError:
                return self.reply(404, {"error": "页面未安装"})

        def do_POST(self):
            action = self.path.removeprefix("/api/")
            if self.path != "/api/" + action or action not in ACTIONS or not self.permitted(mutate=True):
                return self.reply(403, {"error": "未授权的本地管理请求"})
            try:
                sizes = self.headers.get_all("Content-Length") or []
                if (len(sizes) != 1 or not 0 < int(sizes[0]) <= 16384 or self.headers.get("Transfer-Encoding") is not None
                        or self.headers.get("Content-Type") != "application/json"):
                    return self.reply(400, {"error": "无效的请求数据"})
                self.connection.settimeout(4)
                result = manager.call(action, json.loads(self.rfile.read(int(sizes[0]))))
                return self.reply(200, result)
            except (ValueError, TypeError, KeyError) as error:
                # Backend validation errors are intentionally short; never echo request bytes.
                message = str(error)
                safe = bool(type(error) is ValueError and re.match(r"[一-鿿]", message)
                            and len(message) <= 120 and "\n" not in message)
                return self.reply(400, {"error": message if safe else "无效的输入或本地状态无法验证"})
            except (OSError, RuntimeError, subprocess.SubprocessError):
                return self.reply(409, {"error": "操作未确认，请按原 ID 回查，不要重发"})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    host = f"127.0.0.1:{server.server_address[1]}"
    url = "http://" + host
    target = url + "/executors#token=" + token
    try:
        if open_tab and webbrowser.open(target):
            print("执行器管理已打开。按 Ctrl+C 关闭本地服务。", flush=True)
        else:
            print(target, flush=True)  # Intended for the owner on a private terminal.
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("scan")
    register = sub.add_parser("register")
    register.add_argument("route")
    register.add_argument("--codex-home", required=True)
    register.add_argument("--codex-bin")
    init = sub.add_parser("init")
    init.add_argument("--no-open", action="store_true")
    pool = sub.add_parser("pool")
    pool.add_argument("--cwd", required=True)
    submit = sub.add_parser("delegate")
    submit.add_argument("id")
    for field in ("route", "revision", "cwd", "task-file"):
        submit.add_argument("--" + field, required=True)
    for cmd in ("status", "collect"):
        sub.add_parser(cmd).add_argument("id")
    acceptance = sub.add_parser("record-acceptance")
    acceptance.add_argument("id")
    acceptance.add_argument("--verdict", choices=("passed", "failed"), required=True)
    acceptance.add_argument("--reviewer", required=True)
    acceptance.add_argument("--evidence", required=True)
    args = p.parse_args()
    manager = Manager()
    try:
        if args.command == "init":
            jobs.verify_state()
            serve(manager, open_tab=not args.no_open)
            return 0
        if args.command == "register":
            value = manager.register(args.route, args.codex_home, args.codex_bin)
        elif args.command == "scan":
            jobs.verify_state()
            value = {"routes": discover()}
        elif args.command == "pool":
            value = manager.pool(args.cwd)
        elif args.command == "delegate":
            value = manager.call("delegate", {k: v for k, v in vars(args).items() if k != "command"})
        elif args.command == "record-acceptance":
            value = manager.record_acceptance(args)
        else:
            value = manager.original(args.id, collect=args.command == "collect")
        print(jobs.encoded(value).decode(), end="")
        return 0
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
