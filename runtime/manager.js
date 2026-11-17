"use strict";

(() => {
  const refresh = document.querySelector("#refresh");
  const list = document.querySelector("#routes");
  const section = list.closest("section");
  const heading = document.querySelector("#routes-title");
  const pool = document.querySelector("#pool");
  const notice = document.querySelector("#notice");
  const error = document.querySelector("#error");
  const tokenFormat = /^[A-Za-z0-9_-]{20,256}$/;
  const fragment = new URLSearchParams(location.hash.slice(1));
  const token = fragment.get("token") ?? "";
  let busy = false;
  let sessionInvalid = false;
  let state = null;

  // The per-init token lives only in the active manager document.
  if (location.hash) history.replaceState(null, "", location.pathname + location.search);

  const executionLabels = new Map([
    ["pending", "等待执行"], ["queued", "等待执行"], ["running", "执行中"],
    ["submitted", "已提交"], ["completed", "已完成"], ["succeeded", "已完成"],
    ["failed", "失败"], ["unknown", "未知"], ["blocked", "受阻"], ["cancelled", "已取消"],
  ]);
  const acceptanceLabels = new Map([
    ["pending", "待验收"], ["passed", "已通过"], ["failed", "未通过"],
    ["rejected", "未通过"], ["unknown", "未知"], ["not_applicable", "不适用"],
  ]);

  function el(tag, value, className) {
    const node = document.createElement(tag);
    if (value !== undefined && value !== null) node.textContent = String(value);
    if (className) node.className = className;
    return node;
  }

  function readText(value, fallback = "—") {
    return typeof value === "string" && value.length > 0 ? value : fallback;
  }

  function describeKind(kind) {
    if (typeof kind !== "string") return "仅发现";
    if (kind.includes("manual") || kind.includes("desktop")) return "桌面 · 人工协助";
    if (kind === "cli") return "CLI · 只读委派";
    return "仅发现";
  }

  function addStat(dl, label, value, className) {
    const box = el("div");
    box.append(el("dt", label));
    const dd = el("dd", undefined, className);
    dd.append(value instanceof Node ? value : document.createTextNode(value));
    box.append(dd);
    dl.append(box);
  }

  function setError(value = "") {
    // Ignore credentials in an unexpected server error rather than rendering them.
    const human = value && !(token && value.includes(token)) ? value.slice(0, 500) : "";
    error.textContent = human || (value ? "请求未完成，请刷新状态。" : "");
  }

  async function request(path, payload) {
    const headers = new Headers({ "Authorization": "Bearer " + token, "Accept": "application/json" });
    const options = { headers, cache: "no-store", credentials: "omit", redirect: "error" };
    if (payload !== undefined) {
      options.method = "POST";
      options.body = JSON.stringify(payload);
      headers.set("Content-Type", "application/json");
    }
    let response;
    try {
      response = await fetch(path, options);
    } catch {
      throw new Error("暂时连不上本机管理服务。刷新前请勿重复提交。");
    }
    if (response.status === 401 || response.status === 403) {
      sessionInvalid = true;
      throw new Error("本次管理会话无法授权请求。请从本地初始化命令打开管理页。");
    }
    const result = await response.json().catch(() => null);
    if (!response.ok || !result || result.ok === false) {
      throw new Error(readText(result?.error, "请求未完成。请刷新状态，核对原任务是否已提交。"));
    }
    return result;
  }

  function setBusy(value) {
    busy = value;
    section.setAttribute("aria-busy", String(busy));
    refresh.disabled = busy || !tokenFormat.test(token);
    // Keep the invoked control focusable while pending, but make the guard explicit.
    for (const button of list.querySelectorAll("button")) {
      button.setAttribute("aria-disabled", String(busy || sessionInvalid));
    }
  }

  function formField(name, label, value, routeIndex, options = []) {
    const id = `route-${routeIndex}-${name}`;
    const wrapper = el("div", undefined, "field");
    const visible = el("label", label);
    visible.htmlFor = id;
    const input = el(options.length ? "select" : "input");
    input.required = true;
    input.setAttribute("aria-invalid", "false");
    input.name = name;
    input.id = id;
    if (options.length) {
      const placeholder = el("option", "选择档位");
      placeholder.value = "";
      input.append(placeholder);
      for (const option of options) {
        const entry = el("option", option);
        entry.value = option;
        input.append(entry);
      }
      input.value = options.includes(value) ? value : "";
    } else {
      input.type = "text";
      input.spellcheck = false;
      input.autocapitalize = "none";
      input.setAttribute("autocorrect", "off");
      input.value = value;
      if (name === "cwd") {
        input.placeholder = "/绝对路径/项目";
        input.pattern = "/.+";
        input.maxLength = 4096;
        input.title = "输入单个项目目录的绝对路径。";
      } else {
        input.maxLength = 127;
        if (name === "effort") input.placeholder = "例如 medium";
      }
    }
    function synchronizeError() {
      input.setAttribute("aria-invalid", String(!input.validity.valid));
    }
    input.addEventListener("invalid", synchronizeError);
    input.addEventListener("blur", () => {
      if (input.matches(":user-invalid")) synchronizeError();
    });
    input.addEventListener("input", () => {
      if (input.validity.valid) input.setAttribute("aria-invalid", "false");
    });
    wrapper.append(visible, input);
    return wrapper;
  }

  function grantEditor(route, grant, index, open) {
    const details = el("details");
    details.dataset.editRoute = route.id;
    details.open = open;
    const summary = el("summary", grant && !grant.revoked ? "修改项目授权" : "添加项目授权");
    const form = el("form");
    form.setAttribute("aria-labelledby", `route-${index}-grant-title`);
    form.setAttribute("autocomplete", "off");
    form.method = "post";
    form.action = "/api/grant";
    summary.id = `route-${index}-grant-title`;
    form.append(
      formField("cwd", "项目目录（必填）", readText(grant?.cwd, ""), index),
      formField("model", "模型 ID（必填）", readText(grant?.model ?? route.model, ""), index),
      formField("effort", "推理档位（必填）", readText(grant?.effort ?? route.effort, ""), index,
        Array.isArray(route.efforts) ? route.efforts.filter((value) => typeof value === "string") : [])
    );
    const actions = el("div", undefined, "form-actions");
    const save = el("button", "保存只读授权", "primary");
    save.type = "submit";
    save.dataset.control = "grant";
    actions.append(save, el("p", "每次只授权一个目录；修改后，新的授权须重新试跑并验收。", "help"));
    form.append(actions);
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      if (busy || sessionInvalid) return;
      const data = new FormData(form);
      mutate("grant", route, {
        cwd: String(data.get("cwd")),
        model: String(data.get("model")).trim(),
        effort: String(data.get("effort")).trim(),
      }, save);
    });
    details.append(summary, form);
    return details;
  }

  function actionButton(label, action, callback, className) {
    const control = el("button", label, className);
    control.type = "button";
    control.dataset.control = action;
    control.addEventListener("click", () => {
      if (!busy && !sessionInvalid) callback(control);
    });
    return control;
  }

  function routeNode(route, index, open) {
    const item = el("li");
    item.dataset.routeId = route.id;
    const header = el("div", undefined, "route-head");
    const name = readText(route.name, route.id);
    header.append(el("h3", name), el("span", describeKind(route.kind), "route-kind"));
    item.append(header);
    if (name !== route.id) item.append(el("p", route.id, "route-id"));

    const grant = route.grant ?? null;
    const ready = grant?.enabled === true;
    const current = grant && !grant.revoked && grant.bindingCurrent !== false;
    const detected = route.detected === true;
    const info = el("dl", undefined, "info");
    addStat(info, "扫描", detected ? "已发现" : "未发现");
    addStat(info, "项目授权", grant?.revoked ? "已撤销" : grant ? readText(grant.cwd, "已保存") : "未授权");
    addStat(info, "自动委派", ready ? "已启用" : "未启用", ready ? "passed" : undefined);
    item.append(info);
    if (grant && !grant.revoked && !current) {
      item.append(el("p", "执行器、账号或目录的绑定已变化。保存新授权后再试跑。", "route-note blocked"));
    }

    const probe = grant?.probe;
    if (probe) {
      const result = el("dl", undefined, "probe-result");
      addStat(result, "原任务 ID", el("code", readText(probe.id, "待登记"), "job-id"));
      addStat(result, "执行", executionLabels.get(probe.executionStatus) ?? "未知", probe.executionStatus === "failed" ? "failed" : undefined);
      const accepted = acceptanceLabels.get(probe.acceptanceStatus) ?? "待验收";
      addStat(result, "验收", probe.acceptanceStatus === "passed" && !grant.managerConfirmed ? "回执已验收 · 待本页确认" : accepted,
        probe.acceptanceStatus === "passed" && grant.managerConfirmed ? "passed" : undefined);
      item.append(result);
      if (["completed", "succeeded"].includes(probe.executionStatus) && typeof probe.replyMatches === "boolean") {
        item.append(el("p", probe.replyMatches ? "返回结果与原探针口令一致。" : "返回结果与原探针口令不一致，不能启用。",
          probe.replyMatches ? "route-note" : "route-note failed"));
      }
    }

    if (route.kind === "cli" && (detected || grant)) {
      const controls = el("div", undefined, "actions");
      if (current && detected && !probe) {
        controls.append(actionButton("发起只读试跑", "probe", (button) => mutate("probe", route, {}, button), "primary"));
      } else if (current && detected && probe?.id && !grant.managerConfirmed && probe.replyMatches === true
          && ["completed", "succeeded"].includes(probe.executionStatus)
          && ["pending", "passed"].includes(probe.acceptanceStatus)) {
        controls.append(actionButton("确认验收并启用", "accept", (button) => mutate("accept", route, { id: probe.id }, button), "primary"));
      }
      if (grant && !grant.revoked) {
        controls.append(actionButton("撤销授权", "revoke", (button) => mutate("revoke", route, {}, button), "revoke"));
      }
      if (controls.childElementCount) item.append(controls);
      if (detected) item.append(grantEditor(route, grant, index, open));
    } else if (describeKind(route.kind).startsWith("桌面")) {
      item.append(el("p", "按原窗口人工发送、查单和验收。此入口不会加入自动委派池。", "route-note"));
    }
    return item;
  }

  function render(data, previousFocus) {
    const open = new Set([...list.querySelectorAll("details[open]")].map((details) => details.dataset.editRoute));
    const rows = Array.isArray(data.routes) ? data.routes.filter((route) => route && typeof route.id === "string") : [];
    state = data;
    if (!rows.length) {
      list.replaceChildren(el("li", "尚未登记执行器。先在终端运行 register。"));
    } else {
      list.replaceChildren(...rows.map((route, index) => routeNode(route, index, open.has(route.id))));
    }
    const count = Array.isArray(data.pool) ? data.pool.length : rows.filter((route) => route.grant?.enabled).length;
    pool.textContent = `自动委派池：${count} 个入口`;
    if (previousFocus) {
      const route = [...list.children].find((item) => item.dataset.routeId === previousFocus.route);
      const replacement = route && [...route.querySelectorAll("button")].find((button) => button.dataset.control === previousFocus.control);
      (replacement || route?.querySelector("summary, button") || heading).focus({ preventScroll: true });
    }
  }

  async function load(precedingMessage, focus) {
    const response = await request("/api/state");
    sessionInvalid = false;
    render(response, focus);
    notice.textContent = precedingMessage || "已刷新本机发现及试跑状态。";
  }

  async function rescan() {
    if (busy || !tokenFormat.test(token)) return;
    setBusy(true);
    setError();
    notice.textContent = "正在读取已登记的执行器…";
    try {
      await load();
    } catch (failure) {
      notice.textContent = state ? "继续显示上次读取的状态。" : "";
      setError(failure.message);
    } finally {
      setBusy(false);
    }
  }

  async function mutate(action, route, fields, button) {
    setBusy(true);
    setError();
    notice.textContent = "正在提交操作…";
    const focus = { route: route.id, control: button.dataset.control };
    let recorded = false;
    try {
      await request(`/api/${action}`, { route: route.id, revision: route.grant?.revision ?? null, ...fields });
      recorded = true;
      const messages = {
        grant: "已保存只读授权。试跑验收前不会加入自动委派池。",
        probe: "已登记试跑。用原任务 ID 查状态；无需重复提交。",
        accept: "已确认试跑验收。",
        revoke: "已撤销授权，新的自动委派不再允许。",
      };
      await load(messages[action], focus);
    } catch (failure) {
      notice.textContent = recorded ? "操作已提交，刷新才能看到最新状态。" : "";
      setError(failure.message);
      // A request can fail at the browser after the server has persisted its mutation.
      // A read-only refresh is safe; do not replay the submission.
      try {
        await load("已尝试查回当前状态；没有重新提交。", focus);
      } catch {
        // Keep the existing error and last known state if the read also failed.
      }
    } finally {
      setBusy(false);
    }
  }

  refresh.addEventListener("click", rescan);
  if (tokenFormat.test(token)) {
    void rescan();
  } else {
    setBusy(false);
    setError("请通过本地初始化命令打开管理页。");
  }
})();
