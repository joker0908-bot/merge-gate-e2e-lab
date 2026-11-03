#!/usr/bin/env python3
"""SBQB 统一合并门判定：必需检查绿、异厂商 AI 审查通过、无未解决 P0/P1 才写 merge-gate 成功；
非高风险才开启自动合并，高风险由非作者人工合并。"""

from __future__ import annotations

import base64
import json
import os
import re
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urljoin

VENDOR_TOKEN = r"(openai|anthropic|cursor|google|xai|cognition|github|devin)"
AUTHOR_VENDOR_RE = re.compile(rf"(?m)^(?:AI-)?Author-Vendor:\s*{VENDOR_TOKEN}\s*$")
REVIEW_MARKER_RE = re.compile(
    r"<!--\s*sbqb-ai-review\s+"
    rf"vendor={VENDOR_TOKEN}\s+"
    r"head=([a-f0-9]{40})\s+"
    r"verdict=pass\s*-->"
)
FINDINGS_RE = re.compile(r"<!--\s*sbqb-ai-open-findings\s+head=([a-f0-9]{40})\s*-->")
P2_DOWNGRADE_RE = re.compile(r"降级为\s*P2[，,]\s*已开\s*issue\s*#\d+")
SHA_RE = re.compile(r"^[a-f0-9]{40}$")
_SEVERITY_TOKEN_RE = re.compile(r"\[P([012])\]")
_BADGE_SEVERITY_RE = re.compile(
    r"(?:"
    r"!\[[^\]]*?\bP([012])\b[^\]]*?\]\([^)]+\)"
    r"|<img\b[^>]*(?:alt|title)\s*=\s*[\"'][^\"']*\bP([012])\b[^\"']*[\"'][^>]*>"
    r"|https?://(?:img\.)?shields\.io/badge/P([012])(?:[-_/?#]|$)"
    r"|/badge/P([012])(?:[-_/?#]|$)"
    r")",
    re.IGNORECASE,
)
SELF_CHECK = "merge-gate"
GITHUB_ACTIONS_APP_ID = 15368
ACTIONS_BOT = "github-actions[bot]"
PENDING_STATUSES = frozenset({"queued", "in_progress", "pending"})
VENDORS = frozenset({"openai", "anthropic", "cursor", "google", "xai", "cognition", "github", "devin"})
# 写死在判定脚本内，由默认分支执行。键为本仓审查 API 返回的登录名。
BOT_VENDOR_MAP = {
    "chatgpt-codex-connector[bot]": "openai",
    "copilot-pull-request-reviewer[bot]": "github",
    "Copilot": "github",
    "devin-ai-integration[bot]": "devin",
    "cursor[bot]": "cursor",
    # e2e 实验仓专用：本仓无审查机器人，以两个测试账号充当不同厂商审查者；
    # 与上游唯一差异，删除本行及以下例外即恢复上游判定代码。
    "joker0908-bot": "devin",
    "0908Joker": "openai",
}
# e2e 实验仓专用：允许上述两个 User 类型测试账号发可信审查标记。
_E2E_USER_POSTERS = frozenset({"0908joker", "joker0908-bot"})
HIGH_RISK_FILES = frozenset(
    {
        ".github/scripts/merge_gate.py",
        ".github/scripts/test_merge_gate.py",
        ".github/scripts/zizmor_gate.py",
        ".github/sbqb-reviewers.json",
        ".github/sbqb-required-checks.json",
    }
)
HIGH_RISK_PREFIXES = (".github/workflows/", ".github/scripts/", "deploy/")
REQUIRED_CHECKS_PATH = ".github/sbqb-required-checks.json"
AI_REVIEW_NAME = "AI 审查"
RISK_NAME = "高风险"
REVOKE_NAME = "自动合并撤销"
ITEM_NAMES = ("CI", AI_REVIEW_NAME, RISK_NAME, "P0P1 讨论", "head 绑定", REVOKE_NAME)
AI_REVIEW_PENDING_REASON = "当前 head 没有异厂商 AI 审查通过"
HIGH_RISK_PENDING_REASON = "高风险，不自动合并，须由非作者人工核验合并"
INITIAL_PENDING_REASON = "合并门判定中"
UNPARSED_FINDINGS_REASON = "复审 findings 无法解析为级别，失败关闭"
OPEN_FINDINGS_REASON = "复审 findings 仍有未解决的 [P0]/[P1]"
_LEADING_WRAPPER_RE = re.compile(
    r"(?:"
    r"\s+"
    r"|[*_~`#-]+"
    r"|</?(?:sub|sup|strong|b|em|i|p|div|span)(?:\s[^>]*)?>"
    r")+",
    re.IGNORECASE,
)
_BLOCKQUOTE_RE = re.compile(r"^\s*>")
PASS = "通过"
WAIT = "等待"
FAIL = "失败"
WAIT_EXIT = 2
REVOKE_ATTEMPTS = 3
GATE_ERROR_LABEL = "gate-error"
GATE_ERROR_COMMENT = "合并门撤销自动合并后未能确认已取消，已标记 gate-error，本次判定失败关闭。"


class GateError(RuntimeError):
    """读取或启用自动合并失败。"""


@dataclass
class Item:
    name: str
    status: str
    reason: str


@dataclass
class GateResult:
    exit_code: int
    items: list[Item]
    enable_input: dict | None = None
    skipped: bool = False
    summary: str = ""
    commit_state: str = ""
    writeback_aborted: bool = False


@dataclass
class FindingsView:
    present: bool = False
    lines: list[str] | None = None
    recency: tuple = ("", -1)


@dataclass
class PullRequest:
    head: str
    draft: bool = False
    labels: list[str] = field(default_factory=list)
    body: str = ""
    comments: list = field(default_factory=list)
    review_bodies: list = field(default_factory=list)
    threads: list[dict] = field(default_factory=list)
    checks: list[dict] = field(default_factory=list)
    statuses: list[dict] = field(default_factory=list)
    auto_merge_enabled: bool = False
    auto_merge_request: bool = False
    author_login: str = ""
    node_id: str = ""
    number: int = 0
    changed_files: list[str] = field(default_factory=list)
    required_checks: list[dict] = field(default_factory=list)
    ruleset_checks: list[dict] | None = None
    required_checks_error: str = ""
    checks_incomplete: bool = False
    base: str = ""
    default_branch: str = "main"


def render_summary(items: list[Item]) -> str:
    lines = ["| 项目 | 结果 | 原因 |", "|---|---|---|"]
    for item in items:
        reason = item.reason.replace("|", "\\|")
        lines.append(f"| {item.name} | {item.status} | {reason} |")
    return "\n".join(lines) + "\n"


def _item(name: str, status: str, reason: str) -> Item:
    return Item(name=name, status=status, reason=reason)


def _labels(pr: PullRequest) -> set[str]:
    return {str(item).strip() for item in pr.labels if str(item).strip()}


def _normalize_path(path: str) -> str:
    normalized = str(path).replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _high_risk(pr: PullRequest) -> bool:
    if "high-risk" in _labels(pr):
        return True
    for path in pr.changed_files:
        normalized = _normalize_path(path)
        if normalized.startswith(HIGH_RISK_PREFIXES) or normalized in HIGH_RISK_FILES:
            return True
    return False


def _item_names(pr: PullRequest | None = None) -> tuple[str, ...]:
    del pr
    return ITEM_NAMES


def _check_app_id(item: dict) -> int | None:
    if item.get("app_id") is not None:
        try:
            return int(item["app_id"])
        except (TypeError, ValueError):
            return None
    app = item.get("app") if isinstance(item.get("app"), dict) else {}
    if app.get("id") is not None:
        try:
            return int(app["id"])
        except (TypeError, ValueError):
            return None
    if item.get("integration_id") is not None:
        try:
            return int(item["integration_id"])
        except (TypeError, ValueError):
            return None
    return None


def _check_name(item: dict) -> str:
    return str(item.get("name") or item.get("context") or "")


def _normalize_required(items: list[dict] | None) -> set[tuple[str, int]]:
    keys: set[tuple[str, int]] = set()
    for item in items or []:
        if not isinstance(item, dict):
            continue
        name = _check_name(item)
        app_id = _check_app_id(item)
        if name and app_id is not None:
            keys.add((name, app_id))
    return keys


def load_required_checks(text: str | None, *, missing: bool = False) -> tuple[list[dict], str]:
    if missing or text is None:
        return [], "必需检查清单缺失，失败关闭"
    if not str(text).strip():
        return [], "必需检查清单为空，失败关闭"
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return [], "必需检查清单解析失败，失败关闭"
    if not isinstance(data, list) or not data:
        return [], "必需检查清单为空，失败关闭"
    parsed: list[dict] = []
    for item in data:
        if not isinstance(item, dict):
            return [], "必需检查清单解析失败，失败关闭"
        name = _check_name(item)
        app_id = _check_app_id(item)
        if not name or app_id is None:
            return [], "必需检查清单解析失败，失败关闭"
        parsed.append({"name": name, "app_id": app_id})
    return parsed, ""


def extract_ruleset_checks(rules: object) -> list[dict] | None:
    if rules is None:
        return None
    if not isinstance(rules, list):
        return None
    found: list[dict] = []
    for rule in rules:
        if not isinstance(rule, dict) or rule.get("type") != "required_status_checks":
            continue
        parameters = rule.get("parameters") if isinstance(rule.get("parameters"), dict) else {}
        for item in parameters.get("required_status_checks") or []:
            if not isinstance(item, dict):
                continue
            name = str(item.get("context") or item.get("name") or "")
            try:
                app_id = int(item["integration_id"]) if item.get("integration_id") is not None else None
            except (TypeError, ValueError):
                app_id = None
            if name and app_id is not None:
                found.append({"name": name, "app_id": app_id})
    return found


def _check_recency(item: dict) -> tuple[str, int]:
    # 最新一次按创建/启动顺序取，不用 completed_at：旧运行可能更晚结束。
    stamp = str(item.get("created_at") or item.get("started_at") or item.get("updated_at") or "")
    try:
        ident = int(item.get("id") or 0)
    except (TypeError, ValueError):
        ident = 0
    return stamp, ident


def _index_head_checks(pr: PullRequest) -> dict[tuple[str, int], dict]:
    indexed: dict[tuple[str, int], dict] = {}
    for item in list(pr.checks) + list(pr.statuses):
        if not isinstance(item, dict):
            continue
        name = _check_name(item)
        if name == SELF_CHECK:
            continue
        app_id = _check_app_id(item)
        if not name or app_id is None:
            continue
        head = str(item.get("head_sha") or item.get("sha") or pr.head)
        if head and head != pr.head:
            continue
        key = (name, app_id)
        previous = indexed.get(key)
        if previous is None or _check_recency(item) >= _check_recency(previous):
            indexed[key] = item
    return indexed


def _ci_status(pr: PullRequest) -> Item:
    if pr.required_checks_error:
        return _item("CI", FAIL, pr.required_checks_error)
    required = list(pr.required_checks or [])
    if not required:
        return _item("CI", FAIL, "必需检查清单为空，失败关闭")
    required_keys = _normalize_required(required)
    if len(required_keys) != len(required):
        return _item("CI", FAIL, "必需检查清单解析失败，失败关闭")
    if pr.ruleset_checks is not None:
        # merge-gate 自身是 ruleset 必需项，但不在清单里，也不会出现在自己判定时的检查结果中。
        all_ruleset_keys = _normalize_required(pr.ruleset_checks)
        if any(name == SELF_CHECK and app != GITHUB_ACTIONS_APP_ID for name, app in all_ruleset_keys):
            return _item("CI", FAIL, "ruleset 中 merge-gate 的来源不是 GitHub Actions，失败关闭")
        ruleset_keys = {key for key in all_ruleset_keys if key[0] != SELF_CHECK}
        if not ruleset_keys <= required_keys:
            return _item("CI", FAIL, "ruleset 与必需检查清单不一致，失败关闭")
        ruleset_note = "ruleset 已交叉核对"
    else:
        ruleset_note = "ruleset 不可读取"
    if pr.checks_incomplete:
        return _item("CI", FAIL, "检查结果读取失败，失败关闭")
    indexed = _index_head_checks(pr)
    for name, app_id in sorted(required_keys):
        item = indexed.get((name, app_id))
        if item is None:
            return _item("CI", FAIL, f"缺少必需检查 {name}（App {app_id}），失败关闭")
        status = str(item.get("status") or item.get("state") or "").lower()
        conclusion = str(item.get("conclusion") or item.get("state") or "").lower()
        if status in PENDING_STATUSES or conclusion == "pending":
            return _item("CI", FAIL, f"必需检查 {name} 为 pending，失败关闭")
        if conclusion != "success":
            return _item("CI", FAIL, f"必需检查 {name} 为 {conclusion or status or '失败'}，失败关闭")
    return _item("CI", PASS, f"当前 head 的必需检查已通过（{ruleset_note}）")


def _risk_status(pr: PullRequest) -> Item:
    if _high_risk(pr):
        return _item(RISK_NAME, WAIT, HIGH_RISK_PENDING_REASON)
    return _item(RISK_NAME, PASS, "未触及高风险路径")


def _poster(item) -> tuple[str, str, str]:
    if isinstance(item, str):
        return item, "Bot", ""
    if not isinstance(item, dict):
        return "", "", ""
    user = item.get("user") if isinstance(item.get("user"), dict) else {}
    body = str(item.get("body") or "")
    user_type = str(item.get("user_type") or user.get("type") or "")
    login = str(item.get("user_login") or user.get("login") or "")
    return body, user_type, login


def _normalize_login(login: str) -> str:
    key = str(login or "").strip().lower()
    if key.endswith("[bot]"):
        key = key[: -len("[bot]")]
    return key


def _canonical_vendor(vendor: str) -> str:
    raw = str(vendor or "").strip().lower()
    return raw if raw in VENDORS else ""


def _bot_vendor(login: str) -> str:
    raw = str(login or "").strip()
    if not raw:
        return ""
    if raw in BOT_VENDOR_MAP:
        return _canonical_vendor(BOT_VENDOR_MAP[raw])
    want = _normalize_login(raw)
    for key, vendor in BOT_VENDOR_MAP.items():
        if _normalize_login(key) == want:
            return _canonical_vendor(vendor)
    return ""


def _accepted_review_vendor(login: str, claimed: str) -> str:
    mapped = _bot_vendor(login)
    claimed_vendor = _canonical_vendor(claimed)
    if mapped and claimed_vendor and mapped == claimed_vendor:
        return mapped
    return ""


def _author_vendor(pr: PullRequest) -> str:
    # 作者是已知机器人时，厂商以登录名为准；正文可由作者随意编辑，不能用来冒充别家厂商。
    bound = _bot_vendor(str(pr.author_login or ""))
    if bound:
        return bound
    match = AUTHOR_VENDOR_RE.search(pr.body or "")
    return _canonical_vendor(match.group(1) if match else "")


def _trusted_ai_poster(user_type: str, login: str, author_login: str) -> bool:
    if str(user_type or "") == "User" and _normalize_login(login) not in _E2E_USER_POSTERS:
        return False
    if not login or _normalize_login(login) == _normalize_login(author_login):
        return False
    if _normalize_login(login) == _normalize_login(ACTIONS_BOT):
        return False
    return bool(_bot_vendor(login))


def _item_state(item) -> str:
    if not isinstance(item, dict):
        return ""
    return str(item.get("state") or "").upper()


def _item_recency(item) -> tuple[str, int]:
    if not isinstance(item, dict):
        return ("", -1)
    stamp = str(
        item.get("submitted_at")
        or item.get("created_at")
        or item.get("createdAt")
        or item.get("updated_at")
        or item.get("updatedAt")
        or ""
    )
    try:
        ident = int(item.get("id") or 0)
    except (TypeError, ValueError):
        ident = 0
    return stamp, ident


def _item_modified_recency(item) -> tuple[str, int]:
    if not isinstance(item, dict):
        return ("", -1)
    stamp = str(
        item.get("updated_at")
        or item.get("updatedAt")
        or item.get("submitted_at")
        or item.get("created_at")
        or item.get("createdAt")
        or ""
    )
    try:
        ident = int(item.get("id") or 0)
    except (TypeError, ValueError):
        ident = 0
    return stamp, ident


def _trusted_review_item(pr: PullRequest, item) -> dict | None:
    if not isinstance(item, dict):
        return None
    _body, user_type, login = _poster(item)
    if not _trusted_ai_poster(user_type, login, str(pr.author_login or "")):
        return None
    if not _normalize_login(login):
        return None
    return item


def _iter_trusted_comment_items(pr: PullRequest):
    for item in pr.comments:
        trusted = _trusted_review_item(pr, item)
        if trusted is None or _item_state(item) == "DISMISSED":
            continue
        yield trusted


def _iter_latest_review_items(pr: PullRequest):
    latest: dict[str, dict] = {}
    for item in pr.review_bodies:
        trusted = _trusted_review_item(pr, item)
        if trusted is None:
            continue
        key = _normalize_login(_poster(item)[2])
        previous = latest.get(key)
        if previous is None or _item_recency(item) >= _item_recency(previous):
            latest[key] = item
    for item in latest.values():
        if _item_state(item) == "DISMISSED":
            continue
        yield item


def _iter_review_items(pr: PullRequest):
    yield from _iter_trusted_comment_items(pr)
    yield from _iter_latest_review_items(pr)


def _iter_findings_items(pr: PullRequest):
    # findings 不随“同账号最新 review”被替换：同一来源后来不带 findings 块的补充 review
    # 不能让此前仍有效的 findings 消失，因此这里遍历全部未撤销的可信 review。
    yield from _iter_trusted_comment_items(pr)
    for item in pr.review_bodies:
        trusted = _trusted_review_item(pr, item)
        if trusted is None or _item_state(item) == "DISMISSED":
            continue
        yield trusted


def _iter_valid_review_texts(pr: PullRequest):
    for item in _iter_review_items(pr):
        yield _poster(item)


def _cross_vendor_passes(pr: PullRequest, head: str) -> set[str]:
    author = _author_vendor(pr)
    vendors: set[str] = set()
    if not author:
        return vendors
    for text, user_type, login in _iter_valid_review_texts(pr):
        for marker in REVIEW_MARKER_RE.finditer(text or ""):
            accepted = _accepted_review_vendor(login, marker.group(1))
            if accepted and marker.group(2) == head and accepted != author:
                vendors.add(accepted)
    return vendors


def _required_pass_vendors(pr: PullRequest) -> int:
    # 机器人作者的厂商按登录名绑定，1 家异厂商通过即可。人类作者的厂商只能看正文自报，
    # 自报可能不实，因此要 2 家不同厂商都通过：无论作者实际用的是哪家，至少有一家确实是异厂商。
    return 1 if _bot_vendor(str(pr.author_login or "")) else 2


def _ai_review_status(pr: PullRequest, head: str) -> Item:
    vendors = _cross_vendor_passes(pr, head)
    need = _required_pass_vendors(pr)
    shown = "、".join(sorted(vendors))
    if len(vendors) >= need:
        return _item(AI_REVIEW_NAME, PASS, f"异厂商 {shown} 已对当前 head 给出通过")
    if vendors:
        return _item(
            AI_REVIEW_NAME,
            WAIT,
            f"作者厂商只来自正文自报，需要 {need} 家不同厂商通过，当前只有 {shown}",
        )
    return _item(AI_REVIEW_NAME, WAIT, AI_REVIEW_PENDING_REASON)


def _parse_findings_block(block: str) -> list[str] | None:
    content = [line for line in (block or "").splitlines() if line.strip()]
    if not content:
        return []
    open_lines: list[str] = []
    only_p2 = True
    for line in content:
        leading = _comment_leading_severity(line)
        if leading & {"P0", "P1"}:
            open_lines.append(line.lstrip())
            only_p2 = False
        elif "P2" in leading:
            continue
        else:
            only_p2 = False
    if open_lines:
        return open_lines
    if only_p2:
        return []
    return None


def _latest_head_findings(pr: PullRequest, head: str) -> FindingsView:
    # findings 与通过标记分开读：可信审查机器人对当前 head 的 findings 块在任意评论里都算数，
    # 不要求同一条评论带 verdict=pass。按审查来源（可信机器人账号）各取它最新一段明确的 findings 块，
    # 不带 findings 块的后续评论/review 不冲销；各来源 open findings 取并集，一家报空不清另一家。
    by_vendor: dict[str, tuple[tuple[str, int], list[str] | None]] = {}
    for item in _iter_findings_items(pr):
        text, _user_type, login = _poster(item)
        if not _bot_vendor(login):
            continue
        vendor = _normalize_login(login)
        # 同一来源的 findings 按最后编辑时间取最新：旧评论被编辑上报问题不能被后创建的评论冲掉。
        recency = _item_modified_recency(item)
        for found in FINDINGS_RE.finditer(text or ""):
            if found.group(1) != head:
                continue
            rest = (text or "")[found.end() :]
            nxt = FINDINGS_RE.search(rest)
            block = rest if nxt is None else rest[: nxt.start()]
            previous = by_vendor.get(vendor)
            if previous is None or recency >= previous[0]:
                by_vendor[vendor] = (recency, _parse_findings_block(block))
    if not by_vendor:
        return FindingsView()
    recency = ("", -1)
    lines: list[str] = []
    unparsed = False
    for stamp, parsed in by_vendor.values():
        recency = max(recency, stamp)
        if parsed is None:
            unparsed = True
        else:
            lines.extend(parsed)
    return FindingsView(present=True, lines=None if unparsed else lines, recency=recency)


def _findings_on_head(pr: PullRequest, head: str) -> list[str] | None:
    view = _latest_head_findings(pr, head)
    if not view.present:
        return None
    return view.lines


def _clean_rereview_on_head(pr: PullRequest, head: str) -> bool:
    view = _latest_head_findings(pr, head)
    return view.present and view.lines == []


def _resolver_login_and_type(thread: dict) -> tuple[str, str]:
    raw = thread.get("resolvedBy") or thread.get("resolved_by") or {}
    if isinstance(raw, str):
        return raw, ""
    if not isinstance(raw, dict):
        return "", ""
    user = raw.get("user") if isinstance(raw.get("user"), dict) else raw
    return (
        str(user.get("login") or user.get("user_login") or ""),
        str(user.get("type") or user.get("user_type") or user.get("__typename") or ""),
    )


def _author_p2_downgrade_close(thread: dict, author_login: str) -> bool:
    if not thread.get("isResolved"):
        return False
    login, _user_type = _resolver_login_and_type(thread)
    if not login or login != author_login:
        return False
    bodies = _thread_bodies(thread)
    if any(_comment_leading_severity(body) & {"P0", "P1"} for body in bodies):
        return False
    return any(P2_DOWNGRADE_RE.search(body or "") for body in bodies)


def _resolved_by_mechanism(thread: dict, author_login: str) -> bool:
    if not thread.get("isResolved"):
        return False
    if _author_p2_downgrade_close(thread, author_login):
        return True
    login, user_type = _resolver_login_and_type(thread)
    if not login or login == author_login:
        return False
    if user_type == "User":
        return False
    return user_type == "Bot" or login.endswith("[bot]") or bool(_bot_vendor(login))


def _extract_severities(text: str) -> set[str]:
    found: set[str] = set()
    for match in _SEVERITY_TOKEN_RE.finditer(text or ""):
        found.add(f"P{match.group(1)}")
    for match in _BADGE_SEVERITY_RE.finditer(text or ""):
        digit = next((group for group in match.groups() if group is not None), None)
        if digit is not None:
            found.add(f"P{digit}")
    return found


def _first_content_line(text: str) -> str:
    for line in (text or "").splitlines():
        if line.strip():
            return line
    return ""


def _peel_leading_wrappers(line: str) -> str:
    current = line
    while current:
        match = _LEADING_WRAPPER_RE.match(current)
        if not match:
            break
        nxt = current[match.end() :]
        if nxt == current:
            break
        current = nxt
    return current


def _comment_leading_severity(text: str) -> set[str]:
    line = _first_content_line(text)
    if not line:
        return set()
    if _BLOCKQUOTE_RE.match(line):
        return set()
    peeled = _peel_leading_wrappers(line)
    token = re.match(r"\[P([012])\]", peeled)
    if token:
        return {f"P{token.group(1)}"}
    if peeled.startswith(("![", "<img", "http://", "https://")):
        match = _BADGE_SEVERITY_RE.search(peeled)
        if match:
            digit = next((group for group in match.groups() if group is not None), None)
            if digit is not None:
                return {f"P{digit}"}
    return set()


def _is_open_finding_line(line: str) -> bool:
    return bool(_comment_leading_severity(line) & {"P0", "P1"})


def _thread_blocking_reason(thread: dict) -> str | None:
    bodies = _thread_bodies(thread)
    if any(_comment_leading_severity(body) & {"P0", "P1"} for body in bodies):
        return "存在未解决的 [P0]/[P1] 讨论"
    first = bodies[0] if bodies else ""
    if "P2" in _comment_leading_severity(first):
        return None
    return "未标记级别的未解决讨论按 P1 挡合并"


def _blocking_reply(thread: dict) -> bool:
    # 机制解决的是首条发现；之后的回复又报 [P0]/[P1] 时不能跟着一起跳过。
    replies = _thread_comment_items(thread)[1:]
    return any(_comment_leading_severity(_comment_body(item)) & {"P0", "P1"} for item in replies)


def _blocking_thread(thread: dict) -> bool:
    return _thread_blocking_reason(thread) is not None


def _comment_created_at(item) -> str:
    if isinstance(item, dict):
        return str(item.get("created_at") or item.get("createdAt") or "")
    return ""


def _comment_recency(item) -> tuple[str, int]:
    # 行内评论按最后编辑时间计新旧：干净复审之后被编辑为 [P0]/[P1] 的仍是新阻断项。
    if not isinstance(item, dict):
        return ("", -1)
    stamp = str(
        item.get("updated_at") or item.get("updatedAt") or ""
    ) or _comment_created_at(item)
    try:
        ident = int(item.get("id") or 0)
    except (TypeError, ValueError):
        ident = 0
    return stamp, ident


def _thread_comment_items(thread: dict) -> list:
    if not isinstance(thread, dict):
        return []
    raw = thread.get("comments")
    if isinstance(raw, list):
        items = list(raw)
    elif isinstance(raw, dict):
        items = list(raw.get("nodes") or [])
    else:
        items = []
    if not items and thread.get("first") is not None:
        items = [thread.get("first")]
    return items


def _comment_body(item) -> str:
    if isinstance(item, dict):
        return str(item.get("body") or "")
    return str(item or "")


def _thread_started_at(thread: dict) -> tuple[str, int]:
    if not isinstance(thread, dict):
        return ("", -1)
    stamps: list[str] = []
    for key in ("created_at", "createdAt"):
        value = thread.get(key)
        if value:
            stamps.append(str(value))
    items = _thread_comment_items(thread)
    if items:
        first_stamp = _comment_created_at(items[0])
        if first_stamp:
            stamps.append(first_stamp)
    if not stamps:
        return ("", -1)
    return (min(stamps), 0)


def _newer_than_findings(thread: dict, recency: tuple) -> bool:
    if _thread_started_at(thread) > recency:
        return True
    for item in _thread_comment_items(thread):
        if not (_comment_leading_severity(_comment_body(item)) & {"P0", "P1"}):
            continue
        if _comment_recency(item) > recency:
            return True
    return False


def _auto_resolve_clean_threads(
    pr: PullRequest,
    head: str,
    resolve_threads: Callable[[dict], None] | None,
) -> None:
    view = _latest_head_findings(pr, head)
    if not (view.present and view.lines == []):
        return
    for thread in pr.threads:
        if not _blocking_thread(thread) or _resolved_by_mechanism(thread, str(pr.author_login or "")):
            continue
        if _newer_than_findings(thread, view.recency):
            continue
        if resolve_threads is not None:
            resolve_threads(thread)
        thread["isResolved"] = True
        thread["resolvedBy"] = {"login": ACTIONS_BOT, "type": "Bot"}


def _thread_bodies(thread: dict) -> list[str]:
    raw = thread.get("comments")
    bodies: list[str] = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                bodies.append(str(item.get("body") or ""))
            else:
                bodies.append(str(item or ""))
    elif isinstance(raw, dict):
        for item in raw.get("nodes") or []:
            if isinstance(item, dict):
                bodies.append(str(item.get("body") or ""))
    if not bodies and thread.get("first") is not None:
        bodies.append(str(thread.get("first") or ""))
    return [item.lstrip() for item in bodies]


def _thread_status(pr: PullRequest, head: str | None = None) -> Item:
    current = head or pr.head
    view = _latest_head_findings(pr, current)
    if view.present and view.lines is None:
        return _item("P0P1 讨论", FAIL, UNPARSED_FINDINGS_REASON)
    if view.present and view.lines:
        return _item("P0P1 讨论", FAIL, OPEN_FINDINGS_REASON)
    author = str(pr.author_login or "")
    if view.present and view.lines == []:
        newer_blocking = any(
            _blocking_thread(thread) and _newer_than_findings(thread, view.recency) for thread in pr.threads
        )
        if not newer_blocking:
            return _item("P0P1 讨论", PASS, "异厂商复审未再报 P0/P1，已由机制视为解决")
    for thread in pr.threads:
        if (
            _resolved_by_mechanism(thread, author)
            and not (view.present and view.lines == [] and _newer_than_findings(thread, view.recency))
            and not _blocking_reply(thread)
        ):
            continue
        reason = _thread_blocking_reason(thread)
        if reason:
            return _item("P0P1 讨论", FAIL, reason)
    return _item("P0P1 讨论", PASS, "没有未解决的 [P0]/[P1] 讨论")


def _comment_record(item) -> dict:
    if isinstance(item, dict):
        return {
            "body": str(item.get("body") or ""),
            "created_at": str(item.get("createdAt") or item.get("created_at") or ""),
            "updated_at": str(item.get("updatedAt") or item.get("updated_at") or ""),
        }
    return {"body": str(item or ""), "created_at": "", "updated_at": ""}


def collect_review_threads(fetch_page: Callable[[str | None], dict]) -> list[dict]:
    threads: list[dict] = []
    cursor = None
    while True:
        connection = fetch_page(cursor) or {}
        for node in connection.get("nodes") or []:
            comments = ((node or {}).get("comments") or {}).get("nodes") or []
            records = [_comment_record(item) for item in comments]
            if not records:
                records = [_comment_record((node or {}).get("first") or "")]
            resolved = (node or {}).get("resolvedBy") or (node or {}).get("resolved_by") or {}
            created = str((node or {}).get("createdAt") or (node or {}).get("created_at") or "")
            threads.append(
                {
                    "id": str((node or {}).get("id") or ""),
                    "isResolved": bool((node or {}).get("isResolved")),
                    "resolvedBy": resolved,
                    "created_at": created,
                    "first": records[0]["body"] if records else "",
                    "comments": records,
                }
            )
        page = connection.get("pageInfo") or {}
        if not page.get("hasNextPage"):
            break
        cursor = page.get("endCursor")
        _require_complete_page(True, cursor)
    return threads


def _require_complete_page(has_next: bool, *tokens: object) -> None:
    if has_next and not all(str(item or "").strip() for item in tokens):
        raise GateError("pagination_incomplete")


def _current_head(pr: PullRequest, read_head: Callable[[], str] | None) -> str:
    return read_head() if read_head is not None else pr.head


def _head_matches(pr: PullRequest, read_head: Callable[[], str] | None) -> bool:
    return _current_head(pr, read_head) == pr.head


def _off_default_base(pr: PullRequest) -> bool:
    base = str(pr.base or "").strip()
    default = str(pr.default_branch or "").strip()
    return not base or not default or base != default


def _latest_self_status_item(statuses: list) -> dict | None:
    latest: dict | None = None
    latest_key = ("", -1)
    for item in statuses or []:
        if not isinstance(item, dict):
            continue
        context = str(item.get("context") or item.get("name") or "")
        if context != SELF_CHECK:
            continue
        key = _check_recency(item)
        if latest is None or key >= latest_key:
            latest = item
            latest_key = key
    return latest


def _status_state(item: dict) -> str:
    return str(item.get("state") or item.get("conclusion") or "").lower()


def _status_description(item: dict) -> str:
    return str(item.get("description") or "")[:140]


def status_already_written(statuses: list, state: str, description: str = "") -> bool:
    latest = _latest_self_status_item(statuses)
    if latest is None:
        return False
    return _status_state(latest) == state and _status_description(latest) == (description or "")[:140]


def _already_enabled(message: str) -> bool:
    text = str(message or "").lower()
    return "already" in text and "auto" in text


def apply_enable_result(body: dict) -> None:
    if not isinstance(body, dict):
        raise GateError("enable_user_errors")
    data = body.get("data") if isinstance(body.get("data"), dict) else {}
    payload = (
        data.get("enablePullRequestAutoMerge")
        if isinstance(data.get("enablePullRequestAutoMerge"), dict)
        else {}
    )
    user_errors = payload.get("userErrors") if isinstance(payload.get("userErrors"), list) else []
    errors = body.get("errors") if isinstance(body.get("errors"), list) else []
    messages = []
    for item in list(user_errors) + list(errors):
        if isinstance(item, dict):
            messages.append(str(item.get("message") or ""))
        else:
            messages.append(str(item))
    if messages:
        if all(_already_enabled(item) for item in messages):
            return
        raise GateError("enable_user_errors")
    pull = payload.get("pullRequest")
    if not isinstance(pull, dict) or pull.get("number") is None:
        raise GateError("enable_user_errors")


def _revoke(
    pr: PullRequest,
    *,
    disable_auto_merge: Callable[[dict], None] | None,
    read_auto_merge: Callable[[], bool] | None,
    read_head: Callable[[], str] | None,
    add_label: Callable[[str], None] | None,
    post_comment: Callable[[str], None] | None,
    ignore_head: bool = False,
) -> tuple[Item, bool]:
    registered = bool(pr.auto_merge_request)
    if not registered and read_auto_merge is not None:
        registered = bool(read_auto_merge())
    if not registered:
        return _item(REVOKE_NAME, PASS, "当前没有已登记的自动合并"), False
    payload = {"pullRequestId": pr.node_id}
    for _ in range(REVOKE_ATTEMPTS):
        if not ignore_head and not _head_matches(pr, read_head):
            return _item(REVOKE_NAME, FAIL, "head 已变化，放弃本次写回"), True
        try:
            if disable_auto_merge is not None:
                disable_auto_merge(payload)
        except GateError:
            pass
        still = bool(read_auto_merge()) if read_auto_merge is not None else False
        if not still:
            return _item(REVOKE_NAME, PASS, "已撤销并确认"), False
    if add_label is not None:
        add_label(GATE_ERROR_LABEL)
    if post_comment is not None:
        post_comment(GATE_ERROR_COMMENT)
    return _item(REVOKE_NAME, FAIL, "撤销后回读仍登记自动合并"), False


def evaluate(
    pr: PullRequest,
    *,
    enable_auto_merge: Callable[[dict], None] | None = None,
    disable_auto_merge: Callable[[dict], None] | None = None,
    read_head: Callable[[], str] | None = None,
    read_auto_merge: Callable[[], bool] | None = None,
    write_status: Callable[[str, str, str], None] | None = None,
    add_label: Callable[[str], None] | None = None,
    post_comment: Callable[[str], None] | None = None,
    refresh_pr: Callable[[], PullRequest] | None = None,
    resolve_threads: Callable[[dict], None] | None = None,
    _refreshed: bool = False,
) -> GateResult:
    if pr.draft:
        items = [_item(name, WAIT, "草稿拉取请求，跳过") for name in _item_names(pr)]
        result = GateResult(exit_code=0, items=items, skipped=True)
        result.summary = render_summary(items)
        return result
    if _off_default_base(pr):
        items = [_item(name, WAIT, "目标不是默认分支，跳过") for name in _item_names(pr)]
        result = GateResult(exit_code=0, items=items, skipped=True)
        result.summary = render_summary(items)
        return result

    aborted = False
    refreshed_result: GateResult | None = None

    def try_refresh() -> bool:
        nonlocal aborted, refreshed_result
        if refreshed_result is not None:
            return True
        if _head_matches(pr, read_head):
            return False
        if refresh_pr is None or _refreshed:
            aborted = True
            return True
        revoke, _ = _revoke(
            pr,
            disable_auto_merge=disable_auto_merge,
            read_auto_merge=read_auto_merge,
            read_head=read_head,
            add_label=add_label,
            post_comment=post_comment,
            ignore_head=True,
        )
        if revoke.status == FAIL:
            aborted = True
            return True
        refreshed_result = evaluate(
            refresh_pr(),
            enable_auto_merge=enable_auto_merge,
            disable_auto_merge=disable_auto_merge,
            read_head=read_head,
            read_auto_merge=read_auto_merge,
            write_status=write_status,
            add_label=add_label,
            post_comment=post_comment,
            refresh_pr=refresh_pr,
            resolve_threads=resolve_threads,
            _refreshed=True,
        )
        return True

    def write(state: str, description: str, *, initial: bool = False) -> None:
        nonlocal aborted
        if aborted or refreshed_result is not None:
            return
        if try_refresh():
            return
        if write_status is None:
            return
        clipped = (description or "")[:140]
        if initial and _latest_self_status_item(pr.statuses) is not None:
            return
        if not initial and status_already_written(pr.statuses, state, clipped):
            return
        write_status(pr.head, state, clipped)
        pr.statuses.append(
            {
                "context": SELF_CHECK,
                "name": SELF_CHECK,
                "state": state,
                "description": clipped,
                "sha": pr.head,
                "head_sha": pr.head,
            }
        )

    if try_refresh() and refreshed_result is not None:
        return refreshed_result

    write("pending", INITIAL_PENDING_REASON, initial=True)
    if refreshed_result is not None:
        return refreshed_result

    head = pr.head
    if _head_matches(pr, read_head):
        _auto_resolve_clean_threads(pr, head, resolve_threads)
    items = [_ci_status(pr), _ai_review_status(pr, head), _risk_status(pr), _thread_status(pr, head)]
    blockers = [item for item in items if item.status == FAIL]
    waiting = [item for item in items if item.status == WAIT]
    # 只剩“高风险”在等：门禁条件已满足，merge-gate 写成功好让非作者人工合并，但不开启自动合并。
    risk_only = bool(waiting) and all(item.name == RISK_NAME for item in waiting)
    enable_input = None
    keep_auto_merge = False
    commit_state = "failure"
    exit_code = 1
    if blockers:
        items.append(_item("head 绑定", FAIL, "前置条件未满足，未绑定"))
    elif risk_only:
        items.append(_item("head 绑定", PASS, "高风险，未调用自动合并"))
        commit_state = "success"
        exit_code = 0
    elif waiting:
        items.append(_item("head 绑定", WAIT, "前置条件等待中，未绑定"))
        commit_state = "pending"
        exit_code = WAIT_EXIT
    elif not pr.auto_merge_enabled:
        items.append(_item("head 绑定", PASS, "开关未开启，未调用自动合并"))
        commit_state = "success"
        exit_code = 0
    elif try_refresh():
        if refreshed_result is not None:
            return refreshed_result
        items.append(_item("head 绑定", FAIL, "读取后、启用前 head 已变化"))
    else:
        enable_input = {
            "pullRequestId": pr.node_id,
            "expectedHeadOid": head,
            "mergeMethod": "SQUASH",
        }
        try:
            if enable_auto_merge is not None:
                enable_auto_merge(enable_input)
        except GateError as error:
            items.append(_item("head 绑定", FAIL, "开启自动合并失败，失败关闭"))
            if str(error) == "enable_user_errors" and add_label is not None:
                add_label(GATE_ERROR_LABEL)
        else:
            items.append(_item("head 绑定", PASS, "已按当前 head 绑定并请求自动合并"))
            keep_auto_merge = True
            commit_state = "success"
            exit_code = 0

    if keep_auto_merge:
        items.append(_item(REVOKE_NAME, PASS, "条件满足，未撤销"))
    else:
        revoke, revoke_aborted = _revoke(
            pr,
            disable_auto_merge=disable_auto_merge,
            read_auto_merge=read_auto_merge,
            read_head=read_head,
            add_label=add_label,
            post_comment=post_comment,
        )
        items.append(revoke)
        aborted = aborted or revoke_aborted
        if revoke.status == FAIL:
            commit_state = "failure"
            exit_code = 1

    if aborted:
        commit_state = commit_state if commit_state == "pending" else "failure"
        exit_code = exit_code if exit_code != 0 else 1

    result = GateResult(
        exit_code=exit_code,
        items=items,
        enable_input=enable_input if keep_auto_merge else None,
        commit_state=commit_state,
        writeback_aborted=aborted,
    )
    result.summary = render_summary(items)
    if not aborted and refreshed_result is None and commit_state:
        reason = next((item.reason for item in items if item.status != PASS), "通过")
        if risk_only and commit_state == "success":
            reason = HIGH_RISK_PENDING_REASON
        write(commit_state, reason)
    return result


def _request(token: str, method: str, url: str, payload: dict | None = None) -> tuple[object, str]:
    headers = {
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "sbqb-merge-gate",
    }
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
            request, timeout=20
        ) as response:
            raw = response.read(1_000_001)
            if len(raw) > 1_000_000:
                raise GateError("api_response_too_large")
            body = json.loads(raw) if raw else {}
            return body, response.headers.get("Link") or ""
    except GateError:
        raise
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as error:
        # 只有读取允许“不存在”；写状态等请求 404 必须失败关闭，不能当作写成功。
        if isinstance(error, urllib.error.HTTPError) and error.code == 404 and method == "GET":
            return {}, ""
        raise GateError("api_request_failed") from None


def _next_link(link: str) -> str:
    for part in link.split(","):
        section = part.strip()
        if 'rel="next"' in section:
            start = section.find("<")
            end = section.find(">", start + 1)
            if start >= 0 and end > start:
                return section[start + 1 : end]
    return ""


def _paginate(token: str, url: str, list_key: str | None = None) -> list:
    items: list = []
    current = url
    pages = 0
    while current:
        body, link = _request(token, "GET", current)
        if list_key:
            if not isinstance(body, dict) or list_key not in body:
                raise GateError("pagination_incomplete")
            chunk = body.get(list_key)
        else:
            if not isinstance(body, list):
                raise GateError("pagination_incomplete")
            chunk = body
        if not isinstance(chunk, list):
            raise GateError("pagination_incomplete")
        items.extend(chunk)
        pages += 1
        current = _next_link(link)
        if pages > 100:
            raise GateError("pagination_incomplete")
    return items


def _graphql(token: str, query: str, variables: dict) -> dict:
    body, _ = _request(
        token,
        "POST",
        "https://api.github.com/graphql",
        {"query": query, "variables": variables},
    )
    if not isinstance(body, dict):
        raise GateError("graphql_payload_invalid")
    errors = body.get("errors") or []
    if errors:
        message = " ".join(str(item.get("message") or "") for item in errors)
        raise GateError(message or "graphql_failed")
    data = body.get("data")
    if not isinstance(data, dict):
        raise GateError("graphql_payload_invalid")
    return data


class GitHub:
    def __init__(self, token: str, repository: str):
        if not token or "\n" in token or "/" not in repository:
            raise GateError("github_input_invalid")
        self.token = token
        self.owner, self.name = repository.split("/", 1)
        self.rest = f"https://api.github.com/repos/{self.owner}/{self.name}/"

    def get_pull(self, number: int) -> dict:
        body, _ = _request(self.token, "GET", urljoin(self.rest, f"pulls/{number}"))
        if not isinstance(body, dict) or not body.get("number"):
            raise GateError("pull_request_missing")
        return body

    def pulls_for_sha(self, sha: str) -> list[dict]:
        return [
            item
            for item in _paginate(self.token, urljoin(self.rest, f"commits/{sha}/pulls"))
            if isinstance(item, dict)
        ]

    def open_pulls_for_head_sha(self, sha: str) -> list[int]:
        return [
            item["number"]
            for item in _paginate(self.token, urljoin(self.rest, "pulls?state=open&per_page=100"))
            if isinstance(item, dict)
            and isinstance(item.get("number"), int)
            and str((item.get("head") or {}).get("sha") or "") == sha
        ]

    def open_non_draft_pulls(self) -> list[int]:
        default = self.default_branch()
        numbers: list[int] = []
        for item in _paginate(self.token, urljoin(self.rest, "pulls?state=open&per_page=100")):
            if not isinstance(item, dict) or item.get("draft") or not isinstance(item.get("number"), int):
                continue
            base = str((item.get("base") or {}).get("ref") or "")
            if not base or base != default:
                continue
            numbers.append(item["number"])
        return numbers

    def issue_comments(self, number: int) -> list[dict]:
        return [
            item
            for item in _paginate(self.token, urljoin(self.rest, f"issues/{number}/comments?per_page=100"))
            if isinstance(item, dict)
        ]

    def review_comments(self, number: int) -> list[dict]:
        return [
            item
            for item in _paginate(self.token, urljoin(self.rest, f"pulls/{number}/comments?per_page=100"))
            if isinstance(item, dict)
        ]

    def reviews(self, number: int) -> list[dict]:
        return [
            item
            for item in _paginate(self.token, urljoin(self.rest, f"pulls/{number}/reviews?per_page=100"))
            if isinstance(item, dict)
        ]

    def check_runs(self, sha: str) -> list[dict]:
        return [
            item
            for item in _paginate(
                self.token,
                urljoin(self.rest, f"commits/{sha}/check-runs?per_page=100"),
                "check_runs",
            )
            if isinstance(item, dict)
        ]

    def statuses(self, sha: str) -> list[dict]:
        return [
            item
            for item in _paginate(self.token, urljoin(self.rest, f"commits/{sha}/statuses?per_page=100"))
            if isinstance(item, dict)
        ]

    def changed_files(self, number: int) -> list[str]:
        return [
            str(item.get("filename") or "")
            for item in _paginate(self.token, urljoin(self.rest, f"pulls/{number}/files?per_page=100"))
            if isinstance(item, dict)
        ]

    def default_branch(self) -> str:
        body, _ = _request(self.token, "GET", self.rest.rstrip("/"))
        name = str((body or {}).get("default_branch") or "") if isinstance(body, dict) else ""
        return name or "main"

    def add_label(self, number: int, name: str) -> None:
        _request(
            self.token,
            "POST",
            urljoin(self.rest, f"issues/{number}/labels"),
            {"labels": [name]},
        )

    def post_comment(self, number: int, body: str) -> None:
        _request(
            self.token,
            "POST",
            urljoin(self.rest, f"issues/{number}/comments"),
            {"body": body},
        )

    def _get_allow_missing(self, url: str) -> object | None:
        headers = {
            "Authorization": "Bearer " + self.token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "sbqb-merge-gate",
        }
        request = urllib.request.Request(url, method="GET", headers=headers)
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
                request, timeout=20
            ) as response:
                raw = response.read(1_000_001)
                if len(raw) > 1_000_000:
                    raise GateError("api_response_too_large")
                return json.loads(raw) if raw else []
        except urllib.error.HTTPError as error:
            if error.code in {401, 403, 404}:
                return None
            raise GateError("api_request_failed") from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
            raise GateError("api_request_failed") from None

    def required_checks_from_default(self) -> tuple[list[dict], str]:
        branch = self.default_branch()
        raw, _ = _request(
            self.token,
            "GET",
            urljoin(self.rest, f"contents/{REQUIRED_CHECKS_PATH}?ref={branch}"),
        )
        if not isinstance(raw, dict) or not raw.get("content"):
            return [], "必需检查清单缺失，失败关闭"
        content = raw.get("content") or ""
        if raw.get("encoding") == "base64":
            try:
                text = base64.b64decode(content).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                return [], "必需检查清单解析失败，失败关闭"
        else:
            text = str(content)
        return load_required_checks(text)

    def ruleset_checks(self, branch: str) -> list[dict] | None:
        url = urljoin(self.rest, f"rules/branches/{branch}")
        body = self._get_allow_missing(url)
        if body is None:
            return None
        extracted = extract_ruleset_checks(body)
        if extracted is None:
            raise GateError("ruleset_payload_invalid")
        return extracted

    def has_auto_merge(self, number: int) -> bool:
        query = """
        query($owner: String!, $name: String!, $number: Int!) {
          repository(owner: $owner, name: $name) {
            pullRequest(number: $number) { autoMergeRequest { enabledAt } }
          }
        }
        """
        data = _graphql(
            self.token,
            query,
            {"owner": self.owner, "name": self.name, "number": number},
        )
        pull = (data.get("repository") or {}).get("pullRequest") or {}
        return pull.get("autoMergeRequest") is not None

    def _thread_comments(self, thread_id: str, first_page: dict) -> list:
        page = first_page if isinstance(first_page, dict) else {}
        nodes = list(page.get("nodes") or [])
        info = page.get("pageInfo") or {}
        cursor = info.get("endCursor")
        query = """
        query($id: ID!, $cursor: String) {
          node(id: $id) {
            ... on PullRequestReviewThread {
              comments(first: 100, after: $cursor) {
                pageInfo { hasNextPage endCursor }
                nodes { body createdAt updatedAt }
              }
            }
          }
        }
        """
        pages = 0
        while info.get("hasNextPage"):
            _require_complete_page(True, cursor, thread_id)
            data = _graphql(self.token, query, {"id": thread_id, "cursor": cursor})
            chunk = (data.get("node") or {}).get("comments") or {}
            extra = chunk.get("nodes") or []
            if not isinstance(extra, list):
                raise GateError("pagination_incomplete")
            nodes.extend(extra)
            info = chunk.get("pageInfo") or {}
            cursor = info.get("endCursor")
            pages += 1
            if pages > 100:
                raise GateError("pagination_incomplete")
        return nodes

    def review_threads(self, number: int) -> list[dict]:
        query = """
        query($owner: String!, $name: String!, $number: Int!, $cursor: String) {
          repository(owner: $owner, name: $name) {
            pullRequest(number: $number) {
              reviewThreads(first: 100, after: $cursor) {
                pageInfo { hasNextPage endCursor }
                nodes {
                  id
                  isResolved
                  resolvedBy { login __typename }
                  comments(first: 100) {
                    pageInfo { hasNextPage endCursor }
                    nodes { body createdAt updatedAt }
                  }
                }
              }
            }
          }
        }
        """

        def fetch(cursor: str | None) -> dict:
            data = _graphql(
                self.token,
                query,
                {
                    "owner": self.owner,
                    "name": self.name,
                    "number": number,
                    "cursor": cursor,
                },
            )
            connection = ((data.get("repository") or {}).get("pullRequest") or {}).get("reviewThreads") or {}
            for node in connection.get("nodes") or []:
                if not isinstance(node, dict):
                    continue
                node["comments"] = {
                    "nodes": self._thread_comments(str(node.get("id") or ""), node.get("comments") or {})
                }
            return connection

        return collect_review_threads(fetch)

    def write_status(self, sha: str, state: str, description: str) -> None:
        if state not in {"pending", "success", "failure", "error"} or not SHA_RE.fullmatch(sha):
            raise GateError("commit_status_invalid")
        _request(
            self.token,
            "POST",
            urljoin(self.rest, f"statuses/{sha}"),
            {
                "state": state,
                "context": SELF_CHECK,
                "description": (description or "")[:140],
            },
        )

    def enable_auto_merge(self, payload: dict) -> None:
        query = (
            "mutation($input: EnablePullRequestAutoMergeInput!) {"
            " enablePullRequestAutoMerge(input: $input) { pullRequest { number } }"
            "}"
        )
        body, _ = _request(
            self.token,
            "POST",
            "https://api.github.com/graphql",
            {"query": query, "variables": {"input": payload}},
        )
        if not isinstance(body, dict):
            raise GateError("enable_user_errors")
        apply_enable_result(body)

    def disable_auto_merge(self, payload: dict) -> None:
        query = (
            "mutation($input: DisablePullRequestAutoMergeInput!) {"
            " disablePullRequestAutoMerge(input: $input) {"
            "  pullRequest { autoMergeRequest { enabledAt } }"
            " }"
            "}"
        )
        _graphql(self.token, query, {"input": payload})

    def resolve_review_thread(self, thread_id: str) -> None:
        if not thread_id:
            return
        query = """
        mutation($id: ID!) {
          resolveReviewThread(input: {threadId: $id}) {
            thread { isResolved }
          }
        }
        """
        _graphql(self.token, query, {"id": thread_id})


def _write_summary(text: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(text)
        if not text.endswith("\n"):
            handle.write("\n")


def load_event(path: str) -> dict:
    if not path:
        return {}
    with open(path, encoding="utf-8") as handle:
        raw = json.load(handle)
    return raw if isinstance(raw, dict) else {}


def resolve_pull_numbers(event: dict, event_name: str, client: GitHub) -> list[int]:
    if event_name == "schedule":
        return client.open_non_draft_pulls()
    if event_name == "workflow_dispatch":
        raw = os.environ.get("MERGE_GATE_PR_NUMBER") or (event.get("inputs") or {}).get("pr_number")
        try:
            number = int(str(raw or "").strip())
        except ValueError:
            return []
        return [number] if number > 0 else []
    if event_name == "issue_comment":
        issue = event.get("issue") or {}
        if not issue.get("pull_request") or not isinstance(issue.get("number"), int):
            return []
        return [issue["number"]]
    if event_name == "workflow_run":
        run = event.get("workflow_run") or {}
        if str(run.get("name") or "") == SELF_CHECK:
            return []
        numbers: list[int] = []
        for item in run.get("pull_requests") or []:
            if isinstance(item, dict) and isinstance(item.get("number"), int):
                numbers.append(item["number"])
        if numbers:
            return numbers
        sha = run.get("head_sha") or ""
        if SHA_RE.fullmatch(str(sha)):
            numbers = [
                item["number"]
                for item in client.pulls_for_sha(str(sha))
                if isinstance(item.get("number"), int)
            ]
            # fork PR 的 workflow_run 不带 pull_requests，提交也不在本仓分支上：按 head SHA 匹配开放 PR。
            return numbers or client.open_pulls_for_head_sha(str(sha))
        return []
    pull = event.get("pull_request")
    if isinstance(pull, dict) and isinstance(pull.get("number"), int):
        return [pull["number"]]
    return []


def snapshot_from_github(client: GitHub, number: int, enabled: bool) -> PullRequest:
    raw = client.get_pull(number)
    head = str((raw.get("head") or {}).get("sha") or "")
    if not SHA_RE.fullmatch(head):
        raise GateError("head_sha_invalid")
    labels = [str(item.get("name") or "") for item in raw.get("labels") or [] if isinstance(item, dict)]
    author = raw.get("user") if isinstance(raw.get("user"), dict) else {}
    comments = client.issue_comments(number) + client.review_comments(number)
    required, required_error = client.required_checks_from_default()
    default = client.default_branch()
    try:
        checks = client.check_runs(head)
        statuses = client.statuses(head)
        checks_incomplete = False
    except GateError:
        checks, statuses, checks_incomplete = [], [], True
    return PullRequest(
        head=head,
        draft=bool(raw.get("draft")),
        labels=labels,
        body=str(raw.get("body") or ""),
        comments=comments,
        review_bodies=client.reviews(number),
        threads=client.review_threads(number),
        checks=checks,
        statuses=statuses,
        auto_merge_enabled=enabled,
        auto_merge_request=client.has_auto_merge(number),
        author_login=str(author.get("login") or ""),
        node_id=str(raw.get("node_id") or ""),
        number=int(raw.get("number") or number),
        changed_files=client.changed_files(number),
        required_checks=required,
        ruleset_checks=client.ruleset_checks(default),
        required_checks_error=required_error,
        checks_incomplete=checks_incomplete,
        base=str((raw.get("base") or {}).get("ref") or ""),
        default_branch=default,
    )


def _judge_one(client: GitHub, number: int, enabled: bool) -> GateResult:
    raw = client.get_pull(number)
    base = str((raw.get("base") or {}).get("ref") or "")
    default = client.default_branch()
    if raw.get("draft"):
        print(f"#{number} 草稿拉取请求，跳过")
        items = [_item(name, WAIT, "草稿拉取请求，跳过") for name in ITEM_NAMES]
        result = GateResult(exit_code=0, items=items, skipped=True)
        result.summary = render_summary(items)
        return result
    if not base or not default or base != default:
        print(f"#{number} 目标不是默认分支，跳过")
        items = [_item(name, WAIT, "目标不是默认分支，跳过") for name in ITEM_NAMES]
        result = GateResult(exit_code=0, items=items, skipped=True)
        result.summary = render_summary(items)
        return result
    try:
        pr = snapshot_from_github(client, number, enabled)
        return evaluate(
            pr,
            enable_auto_merge=client.enable_auto_merge if enabled else None,
            disable_auto_merge=client.disable_auto_merge,
            read_head=lambda: str((client.get_pull(number).get("head") or {}).get("sha") or ""),
            read_auto_merge=lambda: client.has_auto_merge(number),
            write_status=client.write_status,
            add_label=lambda name: client.add_label(number, name),
            post_comment=lambda body: client.post_comment(number, body),
            refresh_pr=lambda: snapshot_from_github(client, number, enabled),
            resolve_threads=lambda thread: client.resolve_review_thread(str((thread or {}).get("id") or "")),
        )
    except GateError as error:
        head = str((raw.get("head") or {}).get("sha") or "")
        current = str((client.get_pull(number).get("head") or {}).get("sha") or "")
        if SHA_RE.fullmatch(head) and current == head:
            try:
                client.write_status(head, "failure", str(error)[:140])
            except GateError:
                pass
        items = [_item(name, FAIL, str(error)) for name in ITEM_NAMES]
        result = GateResult(exit_code=1, items=items, commit_state="failure")
        result.summary = render_summary(items)
        return result


def main(argv: list[str] | None = None) -> int:
    del argv
    event_name = os.environ.get("GITHUB_EVENT_NAME") or ""
    repository = os.environ.get("GITHUB_REPOSITORY") or ""
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
    enabled = os.environ.get("SBQB_AUTO_MERGE_ENABLED") == "true"
    try:
        event = load_event(os.environ.get("GITHUB_EVENT_PATH") or "")
        client = GitHub(token, repository)
        numbers = resolve_pull_numbers(event, event_name, client)
        if not numbers:
            print("没有关联的拉取请求，跳过")
            return 0
        exit_code = 0
        for number in numbers:
            result = _judge_one(client, number, enabled)
            _write_summary(f"## #{number}\n{result.summary}")
            print(f"## #{number}\n{result.summary}", end="")
            if result.exit_code == 1:
                exit_code = 1
            elif result.exit_code != 0 and exit_code == 0:
                exit_code = result.exit_code
        return exit_code
    except GateError as error:
        text = render_summary([_item(name, FAIL, str(error)) for name in ITEM_NAMES])
        _write_summary(text)
        print(text, end="")
        print(f"判定失败：{error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
