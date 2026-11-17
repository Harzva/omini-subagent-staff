#!/usr/bin/env python3
"""Trusted project's stdio MCP endpoint; never exposed on the Magpie gateway."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import executor_manager as em

NAME = "omini-subagent-staff"
VERSION = "0.2.1"
PROTOCOLS = {"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"}
MAX_MESSAGE = 96 * 1024
ID_SCHEMA = {"type": "string", "description": "原派单 UUID v4，失败或未知仍使用这个 ID。",
             "pattern": "^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$"}
TEXT = {"type": "string", "minLength": 1, "maxLength": 120}
TASK = {"type": "string", "minLength": 1, "maxLength": 16000}
SPEC = {
    "pool": ("列出此项目已授权并验收的自动委派入口。查询不会调用模型。", {}),
    "delegate": ("按原 ID 只读委派到当前项目已验收的入口。失败或未知不要重新派发。",
                 {"id": ID_SCHEMA, "route": TEXT, "revision": ID_SCHEMA, "task": TASK}),
    "status": ("按原 ID 查此项目通过本工具提交的执行与验收状态。", {"id": ID_SCHEMA}),
    "collect": ("按原 ID 取此项目通过本工具提交的脱敏回执与文本结果。", {"id": ID_SCHEMA}),
}


def definitions():
    return [{"name": n, "description": desc,
             "inputSchema": {"type": "object", "properties": props, "required": list(props),
                             "additionalProperties": False}}
            for n, (desc, props) in SPEC.items()]


def safe_view(view):
    return {k: view[k] for k in ("id", "route", "model", "effort", "executionStatus", "acceptanceStatus",
            "nativeStatus", "failureReason", "nativeExecutionObserved", "startedAt", "finishedAt") if k in view}


class Bridge:
    def __init__(self, project, manager):
        self.project, self.identity = em.project(project)
        self.manager = manager

    def call(self, name, args):
        if (name not in SPEC or not isinstance(args, dict) or set(args) != set(SPEC[name][1])
                or any(not isinstance(v, str) or not v.strip() for v in args.values())):
            raise ValueError("工具参数无效")
        if em.project(self.project)[1] != self.identity:
            raise ValueError("当前项目目录已更换，请重新初始化项目连接")
        if name == "pool":
            return {"routes": self.manager.pool(self.project, mcp_identity=self.identity)}
        id = args["id"]
        em.jobs.job_path(id)
        if name == "status":
            return safe_view(self.manager.original(id, mcp_project=self.project, mcp_identity=self.identity))
        if name == "collect":
            value = self.manager.original(id, collect=True, mcp_project=self.project, mcp_identity=self.identity)
            raw = value["receipt"]
            receipt = ({k: raw[k] for k in ("status", "exitCode", "turnCompleted", "hasErrorEvent",
                       "hasFinalResult", "providerRequested", "modelRequested", "effortRequested") if k in raw}
                       if isinstance(raw, dict) else None)
            result = value["result"]
            return {"job": safe_view(value["job"]), "receipt": receipt,
                    "result": result[:12000] if isinstance(result, str) else None,
                    "resultTruncated": isinstance(result, str) and len(result) > 12000}
        content = args["task"].encode("utf-8")
        if len(content) > 16000 or len(args["route"]) > 120 or len(args["revision"]) > 36:
            raise ValueError("委派参数超出长度上限")
        # The manager copies this bounded brief into the durable job before returning.
        em.jobs.verify_state()
        with self.manager.locked():
            root = self.manager.root
        with tempfile.TemporaryDirectory(prefix="mcp-brief-", dir=root) as d:
            brief = Path(d) / "brief.txt"
            em.jobs.private(brief, content)
            return self.manager.call("mcp-delegate",
                                     {"id": id, "route": args["route"], "revision": args["revision"],
                                      "cwd": self.project, "task_file": str(brief)},
                                     mcp_identity=self.identity)


class Protocol:
    def __init__(self, bridge):
        self.bridge = bridge
        self.initialized = False

    def handle(self, msg):
        def result(value):
            return {"jsonrpc":"2.0","id":msg.get("id"),"result":value}

        def error(code, message):
            id = msg.get("id") if isinstance(msg, dict) else None
            return {"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}}

        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
            return error(-32600, "Invalid request")
        method = msg["method"]
        # Notifications cannot invoke tools, even if a caller omits the request ID.
        if "id" not in msg:
            return None
        params = msg.get("params", {})
        if not isinstance(params, dict):
            return error(-32602, "Invalid params")
        if method == "initialize":
            version = params.get("protocolVersion")
            self.initialized = True
            return result({"protocolVersion": version if isinstance(version, str) and version in PROTOCOLS else "2025-06-18",
                           "capabilities":{"tools":{}}, "serverInfo":{"name":NAME,"version":VERSION}})
        if method == "ping":
            return result({})
        if not self.initialized:
            return error(-32002, "Initialize first")
        if method == "tools/list":
            return result({"tools":definitions()})
        if method != "tools/call":
            return error(-32601, "Method not found")
        try:
            name = params.get("name")
            if not isinstance(name, str):
                raise ValueError("无效的工具名称")
            value = self.bridge.call(name, params.get("arguments", {}))
            return result({"content":[{"type":"text","text":json.dumps(value,ensure_ascii=False)}]})
        except (OSError, RuntimeError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as e:
            # Never echo a path, command, native exception or task brief.
            message = str(e)
            safe = (type(e) is ValueError and message and "\u4e00" <= message[0] <= "\u9fff"
                    and "\n" not in message and len(message) <= 120)
            return result({"isError":True,"content":[{"type":"text","text":message if safe else
                "操作未确认；若已提交，使用原 ID 查状态，不要重派。"}]})


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--project", required=True, help="canonical project root supplied by trusted host configuration")
    args = p.parse_args()
    bridge = Bridge(args.project, em.Manager())
    protocol = Protocol(bridge)
    while raw := sys.stdin.buffer.readline(MAX_MESSAGE + 1):
        if len(raw) > MAX_MESSAGE:
            return 2
        try:
            msg = json.loads(raw)
        except (ValueError, UnicodeDecodeError, RecursionError):
            response = {"jsonrpc":"2.0","id":None,"error":{"code":-32700,"message":"Parse error"}}
        else:
            response = protocol.handle(msg)
        if response is not None:
            print(json.dumps(response, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
