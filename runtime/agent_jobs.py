#!/usr/bin/env python3
"""Persistent original-ID dispatch and evidence for explicitly registered Codex CLI profiles."""

import argparse
from contextlib import contextmanager
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import uuid

STATE_VARIABLE = "OMINI_SUBAGENT_STAFF_STATE_DIR"
STATE = Path(os.environ.get(STATE_VARIABLE, str(Path.home() / ".local/state/omini-subagent-staff")))
ROOT = STATE / "jobs"
MANAGER = STATE / "manager-v1"
HOME_EFFORTS = {"low", "medium", "high", "xhigh"}
ROUTE_PATTERN = re.compile(r"[a-z][a-z0-9-]{0,39}")
MODEL_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,126}")
ID_PATTERN = re.compile(r"[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}")
MAX_EVENTS = 32 * 1024**2
MAX_RESULT = 1024**2


def stamp():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def secure_dir(path):
    if not path.is_absolute() or path.resolve() != path:
        raise ValueError("Local state must use a canonical absolute path without symlinks")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    mode = path.lstat()
    if not stat.S_ISDIR(mode.st_mode) or mode.st_uid != os.getuid() or mode.st_mode & 0o077:
        raise ValueError("Local state directories must be private to the current user (0700)")


def verify_state():
    secure_dir(STATE)
    secure_dir(ROOT)
    secure_dir(MANAGER)


def encoded(data):
    return (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode()


def private(path, data):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def atomic(path, data):
    tmp = path.with_name("." + uuid.uuid4().hex + ".tmp")
    private(tmp, data)
    try:
        os.replace(tmp, path)
        sync_dir(path.parent)
    finally:
        tmp.unlink(missing_ok=True)


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def read_regular(path, limit):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), "rb") as f:
        descriptor = os.fstat(f.fileno())
        if not stat.S_ISREG(descriptor.st_mode) or descriptor.st_size > limit:
            raise ValueError("Input must be a regular file within the size limit")
        value = f.read(limit + 1)
    if len(value) > limit:
        raise ValueError("Input exceeds byte limit")
    return value


def read(path):
    return json.loads(read_regular(path, MAX_EVENTS))


def job_path(job_id):
    if not isinstance(job_id, str) or not ID_PATTERN.fullmatch(job_id):
        raise ValueError("ID must be a canonical lowercase UUID v4")
    path = ROOT / job_id
    if path.resolve() != path:
        raise ValueError("Job path contains a symlink")
    return path


def request_at(job):
    try:
        request = read(job / "request.json")
    except FileNotFoundError:
        raise ValueError("Original job request is incomplete; do not redispatch") from None
    if request["id"] != job.name or not ROUTE_PATTERN.fullmatch(request["route"]):
        raise ValueError("Job request identity mismatch")
    return request


def route_specs():
    try:
        return read(MANAGER / "routes.json")
    except FileNotFoundError:
        return {}


def profile_spec(route, codex_home, codex_bin):
    if not ROUTE_PATTERN.fullmatch(route):
        raise ValueError("Route must be 1–40 lowercase letters, decimals or hyphens and start with a letter")
    home = Path(codex_home)
    executable = Path(codex_bin or shutil.which("codex") or "")
    if not home.is_absolute() or not executable.is_absolute():
        raise ValueError("Specify absolute paths for the Codex home and executable")
    home = home.resolve(strict=True)
    if home in {Path.home(), Path("/")}:
        raise ValueError("Use a dedicated Codex configuration directory")
    spec = {"codexHome": str(home), "executable": str(executable), "provider": "openai"}
    bind(spec)
    return spec


def identity(path, *, directory=False):
    s = Path(path).lstat()
    if not (stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode)):
        raise ValueError("Unexpected local binding file type")
    return [s.st_dev, s.st_ino] if directory else [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns]


def bind(spec):
    home = Path(spec["codexHome"])
    binary = Path(spec["executable"]).resolve(strict=True)
    if (not home.is_absolute() or home.resolve(strict=True) != home
            or spec.get("provider") != "openai" or not os.access(binary, os.X_OK)):
        raise ValueError("Invalid Codex CLI profile")
    # Bind the local login by file metadata only. Never read or copy login contents.
    auth = home / "auth.json"
    auth_stat = auth.lstat()
    if auth_stat.st_uid != os.getuid() or stat.S_IMODE(auth_stat.st_mode) & 0o077:
        raise ValueError("Codex auth.json must be private to the current user (0600)")
    return dict(spec, executableResolved=str(binary), executableIdentity=identity(binary),
                homeIdentity=identity(home, directory=True), authIdentity=identity(auth))


def adapter_binding(route):
    try:
        spec = route_specs()[route]
    except KeyError:
        raise ValueError("Codex profile is not registered") from None
    return bind(spec)


def binding_digest(binding):
    return hashlib.sha256(encoded(binding)).hexdigest()


def managed_fingerprint(route):
    return binding_digest(adapter_binding(route))


@contextmanager
def managed_launch(request):
    g = request["managed"]
    with os.fdopen(os.open(MANAGER / "lock", os.O_RDONLY | os.O_NOFOLLOW), "rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_SH)
        grant = read(MANAGER / "grants.json").get(request["route"], {})
        intent = read(MANAGER / f"intent-{request['id']}.json")
        kind = intent.get("kind")
        if (grant.get("revoked") is not False or grant.get("revision") != g["revision"]
                or intent.get("id") != request["id"] or intent.get("revision") != g["revision"]
                or intent.get("route") != request["route"] or grant.get("cwd") != g["project"]
                or grant.get("projectIdentity") != g["projectIdentity"]
                or grant.get("fingerprint") != g["fingerprint"]
                or grant.get("model") != request["model"] or grant.get("effort") != request["effort"]
                or kind not in {"probe", "delegate", "mcp-delegate"}):
            raise ValueError("Managed authorization revoked or changed before launch")
        if kind == "probe":
            probe = grant.get("probe", {})
            if (probe.get("id") != request["id"] or probe.get("cwd") != request["cwd"]
                    or probe.get("taskSha256") != request["taskSha256"]):
                raise ValueError("Managed probe changed before launch")
        elif (request["cwd"] != g["project"] or g["cwdIdentity"] != g["projectIdentity"]
              or (kind == "mcp-delegate" and
                  (intent.get("project") != g["project"] or intent.get("projectIdentity") != g["projectIdentity"]))):
            raise ValueError("Original project binding changed before launch")
        for field, identity_field in ((g["project"], "projectIdentity"), (request["cwd"], "cwdIdentity")):
            p = Path(field)
            if p.resolve(strict=True) != p or identity(p, directory=True) != g[identity_field]:
                raise ValueError("Managed working directory changed before launch")
        binding = adapter_binding(request["route"])
        if binding != request["binding"] or binding_digest(binding) != g["fingerprint"]:
            raise ValueError("Registered profile changed before launch")
        yield binding


def submit(args):
    verify_state()
    job = job_path(args.id)
    task = read_regular(args.task_file, 131072)
    if not task.decode("utf-8").strip():
        raise ValueError("Task must contain 1–131072 UTF-8 bytes")
    cwd = Path(args.cwd)
    if (cwd.resolve(strict=True) != cwd or not cwd.is_dir() or not 1 <= args.timeout <= 3600
            or not MODEL_PATTERN.fullmatch(args.model) or args.effort not in HOME_EFFORTS):
        raise ValueError("Invalid working directory, timeout, model or effort")
    binding = adapter_binding(args.route)
    if binding_digest(binding) != args.managed["fingerprint"]:
        raise ValueError("Registered profile changed before submission")
    try:
        job.mkdir(mode=0o700)
    except FileExistsError:
        raise ValueError("ID already reserved; use status or collect on the original ID") from None
    sync_dir(ROOT)
    request = dict(id=args.id, route=args.route, model=args.model, effort=args.effort, cwd=str(cwd),
                   timeout=args.timeout, submittedAt=stamp(), taskSha256=hashlib.sha256(task).hexdigest(),
                   binding=binding, managed=args.managed)
    private(job / "task.txt", task)
    atomic(job / "request.json", encoded(request))
    with (job / "worker.stderr").open("xb") as err:
        subprocess.Popen([sys.executable, "-B", str(Path(__file__).resolve()), args.id],
                         cwd=job, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=err, start_new_session=True)
    return {"id": args.id, "route": args.route, "dispatch": "submitted_to_local_worker"}


def codex_options(request, job, binding):
    # Ignore personal rules, connectors and provider overrides. Only this explicit
    # profile preauthorizes forwarding its job prompt to the official service.
    cwd = Path(request["cwd"])
    untrusted_projects = ", ".join(
        f'{json.dumps(str(path), ensure_ascii=False)} = {{ trust_level = "untrusted" }}'
        for path in (cwd, *cwd.parents)
    )
    return [binding["executableResolved"], "-a", "never", "exec",
            "--json", "--ephemeral", "--sandbox", "read-only",
            "--ignore-user-config", "--ignore-rules", "--skip-git-repo-check",
            "--cd", request["cwd"], "--model", request["model"], "--color", "never",
            "--output-last-message", str(job / "result.txt"),
            "-c", 'model_provider="openai"', "-c", 'forced_login_method="chatgpt"',
            "-c", 'chatgpt_base_url="https://chatgpt.com/backend-api/"',
            "-c", 'cli_auth_credentials_store="file"', "-c", 'mcp_servers={}',
            "-c", f"projects={{{untrusted_projects}}}", "-c", "project_root_markers=[]",
            "-c", 'web_search="disabled"', "-c", 'project_doc_max_bytes=0',
            "-c", "features.hooks=false", "-c", "features.apps=false",
            "-c", "features.plugins=false", "-c", "features.skill_mcp_dependency_install=false",
            "-c", "skills.include_instructions=false", "-c", "skills.bundled.enabled=false",
            "-c", "features.skill_search=false", "-c", "features.skip_host_skill_discovery=true",
            "-c", "features.browser_use=false", "-c", "features.in_app_browser=false",
            "-c", "features.browser_use_external=false", "-c", "features.browser_use_full_cdp_access=false",
            "-c", "features.browser_annotation_api=false", "-c", "features.computer_use=false",
            "-c", "features.multi_agent=false", "-c", "features.multi_agent_v2=false",
            "-c", "suppress_unstable_features_warning=true", "-c", "check_for_update_on_startup=false",
            "-c", "model_reasoning_effort=" + json.dumps(request["effort"]), "-"]


def codex_environment(binding, job):
    allowed = {"USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "SHELL", "PATH"}
    env = {k: v for k, v in os.environ.items() if k in allowed}
    home = job / "home"
    tmp = job / "tmp"
    home.mkdir(mode=0o700)
    tmp.mkdir(mode=0o700)
    env.update(HOME=str(home), CODEX_HOME=binding["codexHome"], TMPDIR=str(tmp), TMP=str(tmp), TEMP=str(tmp))
    return env


def inspect_events(job):
    seen = {"observed": False, "turnCompleted": False, "turnFailed": False, "hasErrorEvent": False,
            "invalidEventJson": False, "hasFinalResult": False}
    message = None
    try:
        raw = read_regular(job / "events.jsonl", MAX_EVENTS)
    except FileNotFoundError:
        return seen
    except ValueError:
        seen["invalidEventJson"] = True
        return seen
    for line in raw.splitlines():
        try:
            event = json.loads(line)
            kind = event["type"]
            if not isinstance(kind, str):
                raise ValueError("Unexpected event type")
        except (ValueError, KeyError, TypeError, RecursionError):
            seen["invalidEventJson"] = True
            continue
        if kind == "thread.started":
            seen["observed"] = seen["observed"] or bool(isinstance(event.get("thread_id"), str) and event["thread_id"])
        elif kind == "turn.completed":
            seen["turnCompleted"] = True
        elif kind in {"turn.failed", "error"}:
            seen["turnFailed"] = seen["turnFailed"] or kind == "turn.failed"
            seen["hasErrorEvent"] = True
        elif kind == "item.completed" and isinstance(event.get("item"), dict):
            item = event["item"]
            if item.get("type") == "agent_message" and isinstance(item.get("text"), str):
                message = item["text"].strip()
    if message:
        try:
            seen["hasFinalResult"] = read_regular(job / "result.txt", MAX_RESULT).decode().strip() == message
        except (FileNotFoundError, ValueError):
            pass
    return seen


def digest(path, limit):
    return hashlib.sha256(read_regular(path, limit)).hexdigest()


def evidence_digest(job, *, acceptance=False):
    limits = {"request.json": MAX_EVENTS, "task.txt": 131072, "events.jsonl": MAX_EVENTS, "result.txt": MAX_RESULT}
    if acceptance:
        limits["receipt.json"] = MAX_EVENTS
    return {name: digest(job / name, limit) for name, limit in limits.items()}


def worker(job):
    verify_state()
    request = request_at(job)
    with os.fdopen(os.open(job / "worker.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600), "r+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        started_at = stamp()
        private(job / "worker.claim", encoded({"startedAt": started_at}))
        sync_dir(job)
        if digest(job / "task.txt", 131072) != request["taskSha256"]:
            raise ValueError("Task no longer matches its original dispatch")
        exit_code = None
        outcome = "ended"
        with (job / "task.txt").open("rb") as task, (job / "events.jsonl").open("xb") as events, \
             (job / "codex.stderr").open("xb") as err:
            try:
                with managed_launch(request) as binding:
                    process = subprocess.Popen(codex_options(request, job, binding), stdin=task,
                                               stdout=events, stderr=err, start_new_session=True,
                                               cwd=request["cwd"], env=codex_environment(binding, job))
            except (OSError, ValueError, KeyError):
                outcome = "launch_failed"
            else:
                try:
                    exit_code = process.wait(timeout=request["timeout"])
                except subprocess.TimeoutExpired:
                    outcome = "timeout"
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    exit_code = process.wait()
            events.flush()
            os.fsync(events.fileno())
        observed = inspect_events(job)
        if (exit_code == 0 and observed["observed"] and observed["turnCompleted"]
                and not observed["hasErrorEvent"] and not observed["invalidEventJson"] and observed["hasFinalResult"]):
            execution = "completed"
            with (job / "result.txt").open("rb") as result:
                os.fsync(result.fileno())
            artifacts = evidence_digest(job)
        elif outcome == "launch_failed" or (outcome == "ended" and exit_code is not None and exit_code >= 0
                and observed["turnFailed"] and not observed["turnCompleted"]):
            execution, artifacts = "failed", None
        else:
            execution, artifacts = "unknown", None
        receipt = {"id": request["id"], "route": request["route"], "status": execution, "outcome": outcome,
                   "exitCode": exit_code, "providerRequested": "openai", "modelRequested": request["model"],
                   "effortRequested": request["effort"], "taskSha256": request["taskSha256"],
                   "startedAt": started_at, "finishedAt": stamp(), "artifacts": artifacts, **observed}
        atomic(job / "receipt.json", encoded(receipt))


def locked(job):
    try:
        fd = os.open(job / "worker.lock", os.O_RDWR | os.O_NOFOLLOW)
    except FileNotFoundError:
        return False
    with os.fdopen(fd, "r+b") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        return False


def native_receipt(job, request):
    try:
        raw = read(job / "receipt.json")
        expected = {"id": request["id"], "route": request["route"], "modelRequested": request["model"],
                    "effortRequested": request["effort"], "taskSha256": request["taskSha256"],
                    "providerRequested": "openai"}
        if (not isinstance(raw, dict) or any(raw.get(key) != value for key, value in expected.items())
                or raw.get("status") not in ("completed", "failed", "unknown")
                or not isinstance(raw.get("observed"), bool)
                or not all(isinstance(raw.get(key), str) for key in ("outcome", "startedAt", "finishedAt"))):
            return None
        if raw["status"] == "completed" and raw.get("artifacts") != evidence_digest(job):
            return None
        return raw
    except (FileNotFoundError, ValueError, KeyError):
        return None


def snapshot(job):
    request = request_at(job)
    raw = native_receipt(job, request)
    started = False
    if raw:
        execution = raw["status"]
        started = raw["observed"]
    elif locked(job):
        started = inspect_events(job)["observed"]
        execution = "running" if started else "queued"
    else:
        age = (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(request["submittedAt"])).total_seconds()
        execution = "queued" if not (job / "worker.claim").exists() and 0 <= age < 10 else "unknown"
    acceptance = "pending"
    if execution == "completed":
        try:
            verdict = read(job / "acceptance.json")
            if verdict["artifacts"] == evidence_digest(job, acceptance=True):
                acceptance = verdict["verdict"]
        except (FileNotFoundError, ValueError, KeyError):
            pass
    view = {**{k: v for k, v in request.items() if k not in {"binding", "managed"}},
            "executionStatus": execution, "acceptanceStatus": acceptance,
            "nativeStatus": raw["outcome"] if raw else None, "nativeExecutionObserved": started,
            "failureReason": raw["outcome"] if raw and execution != "completed" else None,
            "startedAt": raw["startedAt"] if raw else None, "finishedAt": raw["finishedAt"] if raw else None}
    return view, raw


def status(job):
    view, _ = snapshot(job)
    return view


def collect(job):
    view, raw = snapshot(job)
    result = None
    if view["executionStatus"] == "completed":
        payload = read_regular(job / "result.txt", MAX_RESULT)
        if raw["artifacts"]["result.txt"] != hashlib.sha256(payload).hexdigest():
            raise ValueError("Original evidence changed during collection")
        result = payload.decode()
    return {"job": view, "receipt": raw, "result": result}


def record_acceptance(job, args):
    verify_state()
    view = status(job)
    if view["executionStatus"] != "completed":
        raise ValueError("Only a completed execution can receive an acceptance verdict")
    if args.verdict not in {"passed", "failed"} or not args.reviewer.strip() or not args.evidence.strip():
        raise ValueError("Acceptance requires a verdict, reviewer and evidence")
    tmp = job / (".acceptance-" + uuid.uuid4().hex)
    private(tmp, encoded({"verdict": args.verdict, "reviewer": args.reviewer,
                          "evidence": args.evidence, "checkedAt": stamp(),
                          "artifacts": evidence_digest(job, acceptance=True)}))
    try:
        os.link(tmp, job / "acceptance.json")
        sync_dir(job)
    finally:
        tmp.unlink()
    return status(job)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("id")
    try:
        worker(job_path(parser.parse_args().id))
        return 0
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
