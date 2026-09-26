#!/usr/bin/env python3
"""twg-mcp -- Atlassian's Teamwork Graph CLI (twg) as an MCP server.

Stdlib HTTP on the loopback interface, meant to be reached through a tunnel or
reverse proxy (for example Cloudflare Tunnel), and guarded by a shared bearer
secret kept in ~/.config/twg-mcp/mcp-secret. Configuration comes from
environment variables; see config.example.env.

Two tools, each with an explicit allowlist of twg commands:
  twg_read   read-only commands
  twg_write  commands that change data

twg reads its own credentials from ~/.config/twg. This server never opens
those files, and never logs or returns a token.

  twg-mcp                 serve (what the systemd unit runs)
  twg-mcp --init-secret   create the bearer secret if there is none
  twg-mcp --rotate-secret replace it
  twg-mcp --show-header   print the Authorization header (terminal only)
  twg-mcp --check         print the allowlist sizes and exit
"""

import argparse
import hmac
import http.server
import json
import os
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import urllib.parse

__version__ = "1.0"

def _env_int(name, default):
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        raise SystemExit("%s must be a number" % name)


def _env_list(name):
    return tuple(h.strip().lower() for h in os.environ.get(name, "").split(",") if h.strip())


HOME = os.path.expanduser("~")

# Keep the bind address on the loopback interface and put a tunnel or reverse
# proxy in front; the server has no TLS of its own.
MCP_BIND = os.environ.get("TWG_MCP_BIND", "").strip() or "127.0.0.1"
MCP_PORT = _env_int("TWG_MCP_PORT", 8772)
MCP_SECRET_PATH = os.path.expanduser(
    os.environ.get("TWG_MCP_SECRET_FILE", "").strip()
    or os.path.join("~", ".config", "twg-mcp", "mcp-secret")
)
MCP_VERSIONS = ("2025-03-26", "2025-06-18", "2025-11-25")
MCP_NEWEST = MCP_VERSIONS[-1]
# Public host names (e.g. a Cloudflare Tunnel hostname) this server answers to.
MCP_TUNNEL_HOSTS = _env_list("TWG_MCP_PUBLIC_HOSTS")
MCP_KNOWN_ORIGINS = ("https://claude.ai", "https://claude.com")
MCP_MAX_BODY = 1024 * 1024
MCP_MAX_OUTPUT = 200 * 1024  # bytes of combined stdout+stderr
MCP_COMMAND_TIMEOUT = 120
MCP_MAX_CONCURRENT = 4
MCP_SOCKET_TIMEOUT = 30
MCP_FAIL_LIMIT = 10
MCP_FAIL_WINDOW = 60.0
MCP_LOCKOUT = 60.0

TWG_HOME = os.path.expanduser(os.environ.get("TWG_HOME", "").strip() or HOME)
TWG_PATH = os.environ.get("TWG_PATH", "").strip() or os.pathsep.join(
    [os.path.join(TWG_HOME, ".local", "bin"), "/usr/local/bin", "/usr/bin", "/bin"])
TWG_BIN = os.path.expanduser(os.environ.get("TWG_BIN", "").strip() or (
    shutil.which("twg", path=TWG_PATH) or "twg"))
TWG_ENV = {
    "HOME": TWG_HOME,
    "TWG_AGENT_DEFAULTS": "1",
    "PATH": TWG_PATH,
    "LANG": "C.UTF-8",
}
# twg keeps its credentials in its own config folder; pass it on if set.
if os.environ.get("TWG_CONFIG_DIR"):
    TWG_ENV["TWG_CONFIG_DIR"] = os.environ["TWG_CONFIG_DIR"]

# Optional: shown to the model, e.g. "you@example.com", so it knows whose
# account the tools act as.
TWG_ACCOUNT_LABEL = os.environ.get("TWG_MCP_ACCOUNT_LABEL", "").strip()

# ==========================================================================
# The allowlists. Generated once from `twg --help` walked recursively and the
# help index in ~/.cache/twg/help-index/ (twg 1.3.1), then reviewed by hand.
# A command that is on neither list is refused by both tools, so anything a
# later twg adds stays refused until it is classified here.
# ==========================================================================
READ_COMMANDS = frozenset(
    [
        ('access',),
        ('admin', 'directory', 'list'),
        ('admin', 'group', 'count'),
        ('admin', 'group', 'get'),
        ('admin', 'group', 'list'),
        ('admin', 'group', 'role-assignments'),
        ('admin', 'group', 'stats'),
        ('admin', 'org', 'get'),
        ('admin', 'org', 'list'),
        ('admin', 'user', 'capabilities'),
        ('admin', 'user', 'count'),
        ('admin', 'user', 'get'),
        ('admin', 'user', 'last-active'),
        ('admin', 'user', 'list'),
        ('admin', 'user', 'stats'),
        ('artifacts', 'file', 'get'),
        ('assets', 'graph', 'connections'),
        ('assets', 'graph', 'schema'),
        ('assets', 'object', 'get'),
        ('assets', 'object', 'query'),
        ('assets', 'objects', 'query'),
        ('assets', 'objectschema', 'attributes', 'query'),
        ('assets', 'objectschema', 'get'),
        ('assets', 'objectschema', 'list'),
        ('assets', 'query'),
        ('assets', 'reference-type', 'query'),
        ('assets', 'search'),
        ('assets', 'service-object', 'query'),
        ('assets', 'type', 'get'),
        ('assets', 'type', 'list-attr', 'query'),
        ('assets', 'type', 'query'),
        ('capabilities',),
        ('collaborators',),
        ('commits',),
        ('confluence', 'approvals', 'settings', 'site', 'get'),
        ('confluence', 'approvals', 'settings', 'space', 'get'),
        ('confluence', 'content', 'analytics'),
        ('confluence', 'content', 'approvals', 'enabled'),
        ('confluence', 'content', 'approvals', 'get'),
        ('confluence', 'content', 'approvals', 'history'),
        ('confluence', 'content', 'attachments', 'get'),
        ('confluence', 'content', 'attachments', 'list'),
        ('confluence', 'content', 'body-formats'),
        ('confluence', 'content', 'comments', 'get'),
        ('confluence', 'content', 'comments', 'list'),
        ('confluence', 'content', 'export'),
        ('confluence', 'content', 'export-status'),
        ('confluence', 'content', 'get'),
        ('confluence', 'content', 'get-public-link'),
        ('confluence', 'content', 'history', 'diff'),
        ('confluence', 'content', 'history', 'get'),
        ('confluence', 'content', 'history', 'list'),
        ('confluence', 'content', 'labels', 'list'),
        ('confluence', 'content', 'list'),
        ('confluence', 'content', 'list-available-statuses'),
        ('confluence', 'content', 'macros', 'resolve'),
        ('confluence', 'content', 'macros', 'resolve-status'),
        ('confluence', 'content', 'permissions', 'check'),
        ('confluence', 'content', 'permissions', 'list'),
        ('confluence', 'content', 'reactions', 'list'),
        ('confluence', 'content', 'restriction-state', 'get'),
        ('confluence', 'content', 'status', 'get'),
        ('confluence', 'content', 'tasks', 'get'),
        ('confluence', 'content', 'tasks', 'list'),
        ('confluence', 'content', 'versions', 'diff'),
        ('confluence', 'content', 'versions', 'get'),
        ('confluence', 'content', 'versions', 'list'),
        ('confluence', 'remix', 'maui', 'get'),
        ('confluence', 'search', 'query'),
        ('confluence', 'search', 'text'),
        ('confluence', 'space', 'get'),
        ('confluence', 'space', 'instructions', 'get'),
        ('confluence', 'space', 'list'),
        ('confluence', 'space', 'me'),
        ('confluence', 'space', 'permission', 'available'),
        ('confluence', 'space', 'permission', 'list'),
        ('confluence', 'space', 'role', 'assignment', 'list'),
        ('confluence', 'space', 'role', 'get'),
        ('confluence', 'space', 'role', 'list'),
        ('confluence', 'space', 'role', 'mode'),
        ('confluence', 'templates', 'get'),
        ('confluence', 'templates', 'list'),
        ('confluence', 'tree'),
        ('context', 'confluence', 'blogpost'),
        ('context', 'confluence', 'page'),
        ('context', 'confluence', 'space'),
        ('context', 'confluence', 'whiteboard'),
        ('context', 'get'),
        ('context', 'jira', 'workitem'),
        ('context', 'user'),
        ('csm', 'channel', 'query'),
        ('csm', 'channel', 'query-by-client-name'),
        ('csm', 'context', 'query'),
        ('csm', 'organization', 'get'),
        ('deployments',),
        ('docs', 'get'),
        ('docs', 'query'),
        ('docs', 'search'),
        ('doctor',),
        ('focus-areas', 'get'),
        ('focus-areas', 'query'),
        ('focus-areas', 'search'),
        ('focus-areas-tree',),
        ('goals', 'get'),
        ('goals', 'query'),
        ('goals', 'types'),
        ('help',),
        ('help', 'describe'),
        ('help', 'discover-skills'),
        ('jira', 'board', 'backlog', 'query'),
        ('jira', 'board', 'backlog-view', 'query'),
        ('jira', 'board', 'cells', 'query'),
        ('jira', 'board', 'get'),
        ('jira', 'board', 'projects', 'query'),
        ('jira', 'board', 'query'),
        ('jira', 'board', 'quick-filter', 'get'),
        ('jira', 'board', 'quick-filter', 'query'),
        ('jira', 'board', 'scope', 'query'),
        ('jira', 'board', 'sprints', 'query'),
        ('jira', 'board', 'view-settings', 'query'),
        ('jira', 'dashboard', 'gadget', 'catalog', 'query'),
        ('jira', 'dashboard', 'gadget', 'query'),
        ('jira', 'dashboard', 'get'),
        ('jira', 'dashboard', 'item-property', 'get'),
        ('jira', 'dashboard', 'item-property', 'query'),
        ('jira', 'dashboard', 'query'),
        ('jira', 'filter', 'columns', 'get'),
        ('jira', 'filter', 'get'),
        ('jira', 'filter', 'query'),
        ('jira', 'filter', 'share', 'query'),
        ('jira', 'filter', 'subscription', 'query'),
        ('jira', 'space', 'component', 'counts'),
        ('jira', 'space', 'component', 'get'),
        ('jira', 'space', 'component', 'query'),
        ('jira', 'space', 'get'),
        ('jira', 'space', 'issue-types'),
        ('jira', 'space', 'notification-scheme', 'get'),
        ('jira', 'space', 'query'),
        ('jira', 'space', 'status', 'query'),
        ('jira', 'space', 'types', 'query'),
        ('jira', 'space', 'version', 'counts'),
        ('jira', 'space', 'version', 'get'),
        ('jira', 'space', 'versions', 'query'),
        ('jira', 'sprint', 'get'),
        ('jira', 'sprint', 'snapshot'),
        ('jira', 'sprint', 'workitems', 'query'),
        ('jira', 'workitem', 'attachment', 'get'),
        ('jira', 'workitem', 'attachment', 'query'),
        ('jira', 'workitem', 'bulk-get'),
        ('jira', 'workitem', 'changelog', 'query'),
        ('jira', 'workitem', 'comment', 'query'),
        ('jira', 'workitem', 'field', 'create-metadata'),
        ('jira', 'workitem', 'field', 'update-metadata'),
        ('jira', 'workitem', 'get'),
        ('jira', 'workitem', 'link', 'query'),
        ('jira', 'workitem', 'link-types', 'query'),
        ('jira', 'workitem', 'priorities', 'query'),
        ('jira', 'workitem', 'project-link-candidates', 'query'),
        ('jira', 'workitem', 'property', 'get'),
        ('jira', 'workitem', 'property', 'query'),
        ('jira', 'workitem', 'query'),
        ('jira', 'workitem', 'search'),
        ('jira', 'workitem', 'similar'),
        ('jira', 'workitem', 'statuses', 'query'),
        ('jira', 'workitem', 'transitions', 'query'),
        ('jira', 'workitem', 'types', 'get'),
        ('jira', 'workitem', 'types', 'query'),
        ('jira', 'workitem', 'vote', 'query'),
        ('jira', 'workitem', 'watcher', 'query'),
        ('jira', 'workitem', 'worklog', 'changed'),
        ('jira', 'workitem', 'worklog', 'deleted'),
        ('jira', 'workitem', 'worklog', 'get'),
        ('jira', 'workitem', 'worklog', 'query'),
        ('jsm', 'agents', 'availability', 'get'),
        ('jsm', 'agents', 'availability', 'list'),
        ('jsm', 'agents', 'list'),
        ('jsm', 'alert', 'get'),
        ('jsm', 'alert', 'query'),
        ('jsm', 'approval', 'get'),
        ('jsm', 'approval', 'list'),
        ('jsm', 'conversation', 'message', 'query'),
        ('jsm', 'conversation', 'query'),
        ('jsm', 'conversation', 'settings', 'query'),
        ('jsm', 'conversation', 'workspace', 'query'),
        ('jsm', 'form', 'answers', 'list'),
        ('jsm', 'form', 'fields', 'list'),
        ('jsm', 'form', 'get'),
        ('jsm', 'form', 'list'),
        ('jsm', 'help-article', 'query'),
        ('jsm', 'help-center', 'config', 'get'),
        ('jsm', 'help-center', 'customer-experience', 'list'),
        ('jsm', 'help-center', 'get'),
        ('jsm', 'help-center', 'get-by-project'),
        ('jsm', 'help-center', 'hub-media-config', 'get'),
        ('jsm', 'help-center', 'layout-translations', 'list'),
        ('jsm', 'help-center', 'list'),
        ('jsm', 'help-center', 'list-basic'),
        ('jsm', 'help-center', 'list-by-project'),
        ('jsm', 'help-center', 'media-config', 'get'),
        ('jsm', 'help-center', 'page', 'get'),
        ('jsm', 'help-center', 'page', 'list'),
        ('jsm', 'help-center', 'permission-settings', 'get'),
        ('jsm', 'help-center', 'permissions', 'get'),
        ('jsm', 'help-center', 'product-entities', 'query'),
        ('jsm', 'help-center', 'reporting', 'get'),
        ('jsm', 'help-center', 'topic', 'get'),
        ('jsm', 'help-object-store', 'query'),
        ('jsm', 'incident', 'affected-service', 'query'),
        ('jsm', 'incident', 'affected-services', 'query'),
        ('jsm', 'incident', 'alert', 'query'),
        ('jsm', 'incident', 'get'),
        ('jsm', 'incident', 'query'),
        ('jsm', 'incident', 'responder', 'query'),
        ('jsm', 'knowledge-app-link', 'query'),
        ('jsm', 'knowledge-article', 'query'),
        ('jsm', 'knowledge-base', 'query'),
        ('jsm', 'knowledge-base', 'search', 'query'),
        ('jsm', 'knowledge-capability', 'query'),
        ('jsm', 'knowledge-discovery', 'query'),
        ('jsm', 'knowledge-permission', 'bulk', 'query'),
        ('jsm', 'knowledge-source-type', 'get'),
        ('jsm', 'linked-source', 'query'),
        ('jsm', 'linked-source', 'suggestion', 'query'),
        ('jsm', 'portal', 'query'),
        ('jsm', 'post-incident-review', 'get'),
        ('jsm', 'post-incident-review', 'incident', 'get'),
        ('jsm', 'post-incident-review', 'query'),
        ('jsm', 'request', 'participant', 'list'),
        ('jsm', 'request-type', 'field', 'get'),
        ('jsm', 'request-type', 'fields', 'get'),
        ('jsm', 'request-type', 'query'),
        ('jsm', 'resolution-state', 'get'),
        ('jsm', 'service', 'get'),
        ('jsm', 'service', 'query'),
        ('jsm', 'service', 'search'),
        ('jsm', 'service-tier', 'query'),
        ('jsm', 'sla', 'get'),
        ('jsm', 'sla', 'metrics'),
        ('jsm', 'sla', 'workitems'),
        ('jsm', 'support-site-article', 'query'),
        ('loom', 'get'),
        ('loom', 'space', 'query'),
        ('loom', 'video', 'action-item', 'list'),
        ('loom', 'video', 'agent-brief', 'list'),
        ('loom', 'video', 'comments'),
        ('loom', 'video', 'get'),
        ('loom', 'video', 'transcript'),
        ('meetings', 'get'),
        ('meetings', 'query'),
        ('notifications',),
        ('org-tree',),
        ('people', 'bulk-lookup'),
        ('people', 'describe'),
        ('people', 'search'),
        ('pr-tree',),
        ('projects', 'comments', 'query'),
        ('projects', 'get'),
        ('projects', 'query'),
        ('pull-requests', 'get'),
        ('pull-requests', 'query'),
        ('pull-requests', 'search'),
        ('recently-viewed',),
        ('resolve',),
        ('responsibility', 'get'),
        ('responsibility', 'infer'),
        ('rovo', 'list-apps'),
        ('rovo', 'search'),
        ('search-code', 'diff'),
        ('search-code', 'dir'),
        ('search-code', 'file'),
        ('search-code', 'overview'),
        ('search-code', 'scan'),
        ('search-code', 'search'),
        ('search-code', 'symbol'),
        ('spaces', 'get'),
        ('spaces', 'query'),
        ('subgraph', 'content-references'),
        ('subgraph', 'get'),
        ('subgraph', 'jira-links'),
        ('subgraph', 'space-content'),
        ('talent', 'position', 'get'),
        ('talent', 'position', 'me'),
        ('talent', 'position', 'query'),
        ('teams', 'get'),
        ('teams', 'members', 'list'),
        ('teams', 'query'),
        ('trello', 'board', 'get'),
        ('trello', 'board', 'list', 'query'),
        ('trello', 'board', 'member', 'query'),
        ('trello', 'card', 'get'),
        ('trello', 'card', 'label', 'query'),
        ('trello', 'card', 'member', 'query'),
        ('trello', 'list', 'card', 'query'),
        ('trello', 'list', 'get'),
        ('trello', 'member', 'get'),
        ('trello', 'member', 'me'),
        ('trello', 'member', 'workspace', 'query'),
        ('trello', 'search'),
        ('trello', 'workspace', 'get'),
        ('trello', 'workspace', 'member', 'query'),
        ('user', 'bulk-lookup'),
        ('user', 'direct-reports'),
        ('user', 'get'),
        ('user', 'manager'),
        ('user', 'search'),
        ('user-search',),
        ('videos', 'get'),
        ('videos', 'query'),
        ('whoami',),
        ('work', 'query'),
        ('work', 'search'),
        ('work-tree',),
        ('workitem-tree',),
    ]
)

WRITE_COMMANDS = frozenset(
    [
        ('admin', 'group', 'access', 'grant'),
        ('admin', 'group', 'access', 'revoke'),
        ('admin', 'group', 'create'),
        ('admin', 'group', 'member', 'add'),
        ('admin', 'group', 'member', 'remove'),
        ('admin', 'user', 'cancel-delete'),
        ('admin', 'user', 'delete'),
        ('admin', 'user', 'invite'),
        ('admin', 'user', 'restore'),
        ('admin', 'user', 'suspend'),
        ('api',),
        ('assets', 'object', 'create'),
        ('assets', 'object', 'delete'),
        ('assets', 'object', 'update'),
        ('assets', 'object-attribute-value', 'update'),
        ('assets', 'objectschema', 'create'),
        ('assets', 'objectschema', 'delete'),
        ('assets', 'objectschema', 'settings', 'update'),
        ('assets', 'objectschema', 'update'),
        ('assets', 'reference-type', 'create'),
        ('assets', 'reference-type', 'delete'),
        ('assets', 'reference-type', 'update'),
        ('assets', 'type', 'attribute', 'create'),
        ('assets', 'type', 'attribute', 'delete'),
        ('assets', 'type', 'attribute', 'update'),
        ('assets', 'type', 'create'),
        ('assets', 'type', 'delete'),
        ('assets', 'type', 'update'),
        ('confluence', 'approvals', 'settings', 'site', 'set'),
        ('confluence', 'approvals', 'settings', 'space', 'set'),
        ('confluence', 'content', 'approvals', 'approve'),
        ('confluence', 'content', 'approvals', 'cancel'),
        ('confluence', 'content', 'approvals', 'clear'),
        ('confluence', 'content', 'approvals', 'due-date', 'clear'),
        ('confluence', 'content', 'approvals', 'due-date', 'set'),
        ('confluence', 'content', 'approvals', 'message', 'set'),
        ('confluence', 'content', 'approvals', 'request'),
        ('confluence', 'content', 'approvals', 'request-changes'),
        ('confluence', 'content', 'approvals', 'reviewers', 'update'),
        ('confluence', 'content', 'archive'),
        ('confluence', 'content', 'attachments', 'delete'),
        ('confluence', 'content', 'comments', 'create'),
        ('confluence', 'content', 'comments', 'delete'),
        ('confluence', 'content', 'comments', 'reopen'),
        ('confluence', 'content', 'comments', 'reply'),
        ('confluence', 'content', 'comments', 'resolve'),
        ('confluence', 'content', 'comments', 'update'),
        ('confluence', 'content', 'convert'),
        ('confluence', 'content', 'copy'),
        ('confluence', 'content', 'create'),
        ('confluence', 'content', 'delete-draft'),
        ('confluence', 'content', 'disable-public-link'),
        ('confluence', 'content', 'enable-public-link'),
        ('confluence', 'content', 'labels', 'add'),
        ('confluence', 'content', 'labels', 'remove'),
        ('confluence', 'content', 'labels', 'unwatch'),
        ('confluence', 'content', 'labels', 'watch'),
        ('confluence', 'content', 'move'),
        ('confluence', 'content', 'permissions', 'add'),
        ('confluence', 'content', 'permissions', 'clear'),
        ('confluence', 'content', 'permissions', 'remove'),
        ('confluence', 'content', 'permissions', 'replace'),
        ('confluence', 'content', 'publish'),
        ('confluence', 'content', 'purge'),
        ('confluence', 'content', 'reactions', 'add'),
        ('confluence', 'content', 'reactions', 'remove'),
        ('confluence', 'content', 'restriction-state', 'set'),
        ('confluence', 'content', 'set-owner'),
        ('confluence', 'content', 'star'),
        ('confluence', 'content', 'status', 'set'),
        ('confluence', 'content', 'tasks', 'complete'),
        ('confluence', 'content', 'tasks', 'reopen'),
        ('confluence', 'content', 'trash'),
        ('confluence', 'content', 'unarchive'),
        ('confluence', 'content', 'unstar'),
        ('confluence', 'content', 'untrash'),
        ('confluence', 'content', 'unwatch'),
        ('confluence', 'content', 'update'),
        ('confluence', 'content', 'versions', 'restore'),
        ('confluence', 'content', 'watch'),
        ('confluence', 'space', 'archive'),
        ('confluence', 'space', 'create'),
        ('confluence', 'space', 'delete'),
        ('confluence', 'space', 'instructions', 'set'),
        ('confluence', 'space', 'role', 'create'),
        ('confluence', 'space', 'role', 'update'),
        ('confluence', 'space', 'star'),
        ('confluence', 'space', 'unarchive'),
        ('confluence', 'space', 'unstar'),
        ('confluence', 'space', 'unwatch'),
        ('confluence', 'space', 'update'),
        ('confluence', 'space', 'watch'),
        ('goals', 'archive'),
        ('goals', 'create'),
        ('goals', 'status-update', 'create'),
        ('goals', 'status-update', 'update'),
        ('goals', 'update'),
        ('jira', 'board', 'create'),
        ('jira', 'board', 'delete'),
        ('jira', 'dashboard', 'bulk-edit'),
        ('jira', 'dashboard', 'copy'),
        ('jira', 'dashboard', 'create'),
        ('jira', 'dashboard', 'delete'),
        ('jira', 'dashboard', 'gadget', 'add'),
        ('jira', 'dashboard', 'gadget', 'delete'),
        ('jira', 'dashboard', 'gadget', 'update'),
        ('jira', 'dashboard', 'item-property', 'delete'),
        ('jira', 'dashboard', 'item-property', 'set'),
        ('jira', 'dashboard', 'update'),
        ('jira', 'field', 'cancel-delete'),
        ('jira', 'field', 'create'),
        ('jira', 'field', 'delete'),
        ('jira', 'field', 'update'),
        ('jira', 'filter', 'add-favourite'),
        ('jira', 'filter', 'change-owner'),
        ('jira', 'filter', 'columns', 'set'),
        ('jira', 'filter', 'create'),
        ('jira', 'filter', 'delete'),
        ('jira', 'filter', 'remove-favourite'),
        ('jira', 'filter', 'reset-columns'),
        ('jira', 'filter', 'share', 'add'),
        ('jira', 'filter', 'share', 'remove'),
        ('jira', 'filter', 'update'),
        ('jira', 'space', 'archive'),
        ('jira', 'space', 'component', 'create'),
        ('jira', 'space', 'component', 'delete'),
        ('jira', 'space', 'component', 'update'),
        ('jira', 'space', 'create'),
        ('jira', 'space', 'delete'),
        ('jira', 'space', 'restore'),
        ('jira', 'space', 'update'),
        ('jira', 'space', 'version', 'create'),
        ('jira', 'space', 'version', 'delete'),
        ('jira', 'space', 'version', 'merge'),
        ('jira', 'space', 'version', 'move'),
        ('jira', 'space', 'version', 'update'),
        ('jira', 'sprint', 'complete'),
        ('jira', 'sprint', 'create'),
        ('jira', 'sprint', 'delete'),
        ('jira', 'sprint', 'start'),
        ('jira', 'sprint', 'update'),
        ('jira', 'workitem', 'archive'),
        ('jira', 'workitem', 'attachment', 'delete'),
        ('jira', 'workitem', 'bulk-transition'),
        ('jira', 'workitem', 'clone'),
        ('jira', 'workitem', 'comment', 'create'),
        ('jira', 'workitem', 'comment', 'delete'),
        ('jira', 'workitem', 'comment', 'update'),
        ('jira', 'workitem', 'create'),
        ('jira', 'workitem', 'create-bulk'),
        ('jira', 'workitem', 'delete'),
        ('jira', 'workitem', 'link', 'artifact'),
        ('jira', 'workitem', 'link', 'branch'),
        ('jira', 'workitem', 'link', 'build'),
        ('jira', 'workitem', 'link', 'commit'),
        ('jira', 'workitem', 'link', 'deployment'),
        ('jira', 'workitem', 'link', 'goal'),
        ('jira', 'workitem', 'link', 'loom'),
        ('jira', 'workitem', 'link', 'meeting'),
        ('jira', 'workitem', 'link', 'page'),
        ('jira', 'workitem', 'link', 'pr'),
        ('jira', 'workitem', 'link', 'project'),
        ('jira', 'workitem', 'link', 'repo'),
        ('jira', 'workitem', 'link', 'weblink'),
        ('jira', 'workitem', 'link', 'workitem'),
        ('jira', 'workitem', 'property', 'delete'),
        ('jira', 'workitem', 'property', 'set'),
        ('jira', 'workitem', 'transition'),
        ('jira', 'workitem', 'unarchive'),
        ('jira', 'workitem', 'unlink', 'artifact'),
        ('jira', 'workitem', 'unlink', 'branch'),
        ('jira', 'workitem', 'unlink', 'build'),
        ('jira', 'workitem', 'unlink', 'commit'),
        ('jira', 'workitem', 'unlink', 'deployment'),
        ('jira', 'workitem', 'unlink', 'goal'),
        ('jira', 'workitem', 'unlink', 'loom'),
        ('jira', 'workitem', 'unlink', 'meeting'),
        ('jira', 'workitem', 'unlink', 'page'),
        ('jira', 'workitem', 'unlink', 'pr'),
        ('jira', 'workitem', 'unlink', 'project'),
        ('jira', 'workitem', 'unlink', 'repo'),
        ('jira', 'workitem', 'unlink', 'weblink'),
        ('jira', 'workitem', 'unlink', 'workitem'),
        ('jira', 'workitem', 'update'),
        ('jira', 'workitem', 'vote', 'add'),
        ('jira', 'workitem', 'vote', 'remove'),
        ('jira', 'workitem', 'watcher', 'add'),
        ('jira', 'workitem', 'watcher', 'remove'),
        ('jira', 'workitem', 'worklog', 'add'),
        ('jira', 'workitem', 'worklog', 'delete'),
        ('jira', 'workitem', 'worklog', 'update'),
        ('jsm', 'agents', 'availability', 'set'),
        ('jsm', 'alert', 'create'),
        ('jsm', 'alert', 'delete'),
        ('jsm', 'alert', 'update'),
        ('jsm', 'approval', 'approve'),
        ('jsm', 'approval', 'reject'),
        ('jsm', 'conversation', 'claim', 'create'),
        ('jsm', 'conversation', 'close', 'create'),
        ('jsm', 'conversation', 'settings', 'update'),
        ('jsm', 'conversation', 'workspace', 'create'),
        ('jsm', 'help-center', 'create'),
        ('jsm', 'help-object-store', 'create'),
        ('jsm', 'incident', 'create'),
        ('jsm', 'incident', 'delete'),
        ('jsm', 'incident', 'link', 'affected-service'),
        ('jsm', 'incident', 'link', 'alert'),
        ('jsm', 'incident', 'responder', 'add'),
        ('jsm', 'incident', 'responder', 'remove'),
        ('jsm', 'incident', 'transition'),
        ('jsm', 'incident', 'unlink', 'affected-service'),
        ('jsm', 'incident', 'unlink', 'alert'),
        ('jsm', 'incident', 'update'),
        ('jsm', 'knowledge-base', 'create'),
        ('jsm', 'knowledge-discovery', 'create'),
        ('jsm', 'linked-source', 'link'),
        ('jsm', 'linked-source', 'permission', 'update'),
        ('jsm', 'linked-source', 'unlink'),
        ('jsm', 'linked-source', 'view', 'update'),
        ('jsm', 'post-incident-review', 'create'),
        ('jsm', 'post-incident-review', 'delete'),
        ('jsm', 'post-incident-review', 'link', 'incident'),
        ('jsm', 'post-incident-review', 'unlink', 'incident'),
        ('jsm', 'post-incident-review', 'update'),
        ('jsm', 'request', 'create'),
        ('jsm', 'request', 'participant', 'add'),
        ('jsm', 'request', 'participant', 'remove'),
        ('loom', 'folder', 'create'),
        ('loom', 'invite', 'accept'),
        ('loom', 'space', 'create'),
        ('loom', 'video', 'comment', 'create'),
        ('loom', 'video', 'delete'),
        ('loom', 'video', 'move'),
        ('loom', 'video', 'reaction', 'add'),
        ('loom', 'video', 'recover'),
        ('loom', 'video', 'rename'),
        ('loom', 'video', 'share'),
        ('loom', 'video', 'visibility', 'set'),
        ('loom', 'workspace', 'join'),
        ('projects', 'archive'),
        ('projects', 'comments', 'create'),
        ('projects', 'create'),
        ('projects', 'status-update', 'create'),
        ('projects', 'status-update', 'update'),
        ('projects', 'update'),
        ('teams', 'archive'),
        ('teams', 'create'),
        ('teams', 'members', 'add'),
        ('teams', 'members', 'remove'),
        ('teams', 'update'),
        ('trello', 'board', 'close'),
        ('trello', 'board', 'reopen'),
        ('trello', 'board', 'update'),
        ('trello', 'card', 'add-label'),
        ('trello', 'card', 'add-member'),
        ('trello', 'card', 'archive'),
        ('trello', 'card', 'create'),
        ('trello', 'card', 'mark-complete'),
        ('trello', 'card', 'remove-label'),
        ('trello', 'card', 'remove-member'),
        ('trello', 'card', 'unarchive'),
        ('trello', 'card', 'update'),
        ('trello', 'list', 'card', 'sort'),
    ]
)

REFUSED_COMMANDS = {
    ('admin', 'auth', 'login'): 'credentials',
    ('admin', 'auth', 'logout'): 'credentials',
    ('admin', 'auth', 'status'): 'credentials',
    ('admin', 'auth', 'switch'): 'credentials',
    ('artifacts', 'file', 'create'): 'uploads a file from the server machine',
    ('artifacts', 'file', 'update'): 'uploads a file from the server machine',
    ('auth', 'refresh'): 'credentials',
    ('auth', 'storage', 'migrate'): 'credentials',
    ('auth', 'storage', 'reset'): 'credentials',
    ('auth', 'storage', 'rotate-key'): 'credentials',
    ('auth', 'storage', 'status'): 'credentials',
    ('benchmark', 'lite'): 'spawns local agent sessions and writes local files',
    ('benchmark', 'lite', 'check'): 'spawns local agent sessions and writes local files',
    ('benchmark', 'lite', 'doctor'): 'spawns local agent sessions and writes local files',
    ('benchmark', 'lite', 'plan'): 'spawns local agent sessions and writes local files',
    ('benchmark', 'lite', 'report'): 'spawns local agent sessions and writes local files',
    ('benchmark', 'lite', 'run'): 'spawns local agent sessions and writes local files',
    ('cache', 'clear'): 'local configuration cache',
    ('completion', 'script'): 'local shell setup',
    ('confluence', 'content', 'attachments', 'download'): 'writes a file on the server machine',
    ('confluence', 'content', 'attachments', 'upload'): 'uploads a file from the server machine',
    ('consent',): 'CLI configuration',
    ('env',): 'auth mode / environment (can print credentials)',
    ('env', 'auth'): 'auth mode / environment (can print credentials)',
    ('feedback',): 'opens a browser on the server machine',
    ('jira', 'workitem', 'attachment', 'download'): 'writes a file on the server machine',
    ('jira', 'workitem', 'attachment', 'thumbnail'): 'writes a file on the server machine',
    ('jira', 'workitem', 'attachment', 'upload'): 'uploads a file from the server machine',
    ('login',): 'credentials',
    ('logout',): 'credentials',
    ('loom', 'video', 'upload'): 'uploads a file from the server machine',
    ('rovo', 'auth'): 'connector authentication',
    ('setup',): 'installation/credentials setup',
    ('setup', 'bitbucket'): 'installation/credentials setup',
    ('setup', 'default-site'): 'installation/credentials setup',
    ('skills', 'install'): 'local installation',
    ('skills', 'uninstall'): 'local installation',
    ('uninstall',): 'installation',
    ('upgrade',): 'installation',
    ('upkeep', 'disable'): 'OAuth upkeep scheduler',
    ('upkeep', 'enable'): 'OAuth upkeep scheduler',
    ('upkeep', 'run'): 'OAuth upkeep scheduler',
    ('upkeep', 'status'): 'OAuth upkeep scheduler',
    ('visualize',): 'reads and writes local files / opens a browser',
}

# Whole command families refused by both tools, checked against the first word
# before and after alias resolution.
REFUSED_FAMILIES = {
    "bitbucket": "Bitbucket is handled by the separate bb connector.",
    "bb": "Bitbucket is handled by the separate bb connector.",
    "login": "it manages twg credentials.",
    "logout": "it manages twg credentials.",
    "auth": "it manages twg credentials.",
    "env": "it manages the twg auth mode and can print credentials.",
    "setup": "it installs twg and sets up credentials.",
    "update": "it upgrades the twg installation.",
    "upgrade": "it upgrades the twg installation.",
    "uninstall": "it removes the twg installation.",
    "upkeep": "it manages the OAuth upkeep scheduler.",
    "consent": "it changes twg's local configuration.",
    "skills": "it changes the local skill installation.",
    "cache": "it changes twg's local configuration cache.",
    "completion": "it is local shell setup.",
    "benchmark": "it spawns local agent sessions and writes local files.",
    "feedback": "it opens a browser on the server machine.",
    "visualize": "it reads and writes files on the server machine.",
    "visualise": "it reads and writes files on the server machine.",
}

# Words that may appear anywhere and are refused for a given command.
REFUSED_FLAGS = {
    ("doctor",): ("--fix",),
}

# Options that would make twg read or write a file on the server machine. A remote
# caller could otherwise upload ~/.config/twg/auth.conf to Confluence.
FILE_OPTIONS = frozenset(
    [
        "--attributes-file",
        "--body-file",
        "--context-content-file",
        "--edits-file",
        "--file",
        "--file-local",
        "--files-from",
        "--in",
        "--input",
        "--input-file",
        "--out",
        "--out-dir",
        "--output-dir",
        "--output-path",
        "--prompt-file",
        "--report-file",
        "--result-file",
        "--role-assignments-file",
        "--sqlite-file",
        "--variables-file",
    ]
)

# Aliases twg (commander) accepts, per parent path, mapped to canonical words.
ALIASES = {
    (): {
        "bb": "bitbucket",
        "pull-requests-tree": "pr-tree",
        "issue-tree": "workitem-tree",
        "status-rollup": "work-tree",
        "visualise": "visualize",
        "ownership": "responsibility",
        "update": "upgrade",
    },
    ("assets",): {"schema": "objectschema", "schemas": "objectschema",
                  "referencetype": "reference-type"},
    ("assets", "graph"): {"connection": "connections"},
    ("assets", "objectschema"): {"query": "list"},
    ("assets", "type"): {"list-attributes": "list-attr"},
    ("bitbucket",): {"prs": "pull-requests"},
    ("confluence", "content"): {"comment": "comments"},
    ("confluence", "space"): {"restore": "unarchive"},
    ("csm",): {"organisation": "organization"},
    ("jira", "space"): {"list": "query"},
    ("jira", "workitem"): {"custom-fields": "field"},
    ("jsm",): {"help-centre": "help-center"},
    ("jsm", "alert"): {"list": "query"},
    ("jsm", "incident"): {"list": "query"},
    ("jsm", "request"): {"participants": "participant"},
    ("jsm", "service"): {"list": "query"},
    ("loom",): {"videos": "video"},
    ("rovo",): {"list-connectors": "list-apps"},
}

KNOWN_PREFIXES = frozenset(
    p[:i]
    for p in list(READ_COMMANDS) + list(WRITE_COMMANDS) + list(REFUSED_COMMANDS)
    for i in range(1, len(p) + 1)
)

# Shapes of credential values, redacted from any output without ever reading
# twg's credential files: JWTs, Atlassian API tokens, and Bearer headers.
TOKEN_PATTERNS = [
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    re.compile(r"\bATAT[A-Za-z0-9_=-]{20,}"),
    re.compile(r"\bATCTT[A-Za-z0-9_=-]{20,}"),
    re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{16,}"),
    re.compile(r'(?i)("?(access|refresh|id)_?token"?\s*[:=]\s*"?)[A-Za-z0-9._~+/=-]{16,}'),
]


def top_level_words(paths):
    return sorted({p[0] for p in paths})


def grouped(paths):
    """'jira workitem: create, update' lines, for the instructions."""
    groups = {}
    for p in sorted(paths):
        parent = " ".join(p[:-1])
        groups.setdefault(parent, []).append(p[-1])
    lines = []
    for parent in sorted(groups):
        words = ", ".join(groups[parent])
        lines.append("  %s: %s" % (parent, words) if parent else "  " + words)
    return "\n".join(lines)


READ_TOPS = top_level_words(READ_COMMANDS)
WRITE_TOPS = top_level_words(WRITE_COMMANDS)

MCP_INSTRUCTIONS = """\
twg is Atlassian's Teamwork Graph CLI (Jira, Confluence, JSM, Assets, Goals,
Projects, Teams, Loom, Trello, Rovo search, code search, people and org
context), offered here as two tools%s.

twg_read runs read-only commands. twg_write runs commands that change data.
Both take one argument, args: the words that would follow `twg`, command first.
Example: {"args": ["jira", "workitem", "get", "PROJ-123", "-o", "json"]}

Put global options (-o json, --output-summary inline, --select ...) after the
command words, never before. Agent defaults are on, so large results come back
as a summary; add "--output-summary", "inline" to get the whole payload inline
(output is capped at 200 KB). For help, run {"args": ["help", "describe",
"jira workitem create"]} with twg_read, or add --help to any allowed command
with the tool that would run it.

Bitbucket is not here: use the separate bb connector for it. Refused by both
tools: bitbucket/bb, login, logout, auth, env, setup, update, upgrade,
uninstall, upkeep, consent, skills, cache, completion, benchmark, feedback,
visualize, doctor --fix, admin auth, rovo auth, anything that uploads a file
from or downloads a file to the server machine, and every option that names a local
file (--body-file, --input-file, --variables-file, ...). Pass text inline
instead (--body, --input-json, --variables-json).

Read-only commands (twg_read)
%s

Commands that change data (twg_write)
%s
""" % ((", signed in as %s" % TWG_ACCOUNT_LABEL) if TWG_ACCOUNT_LABEL else "",
       grouped(READ_COMMANDS), grouped(WRITE_COMMANDS))

MCP_TOOL_INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "args": {
            "type": "array",
            "items": {"type": "string"},
            "description": 'The words after `twg`, command first, for example '
            '["jira", "workitem", "query", "--jql", "assignee = currentUser()"].',
        }
    },
    "required": ["args"],
    "additionalProperties": False,
}

MCP_TOOLS = [
    {
        "name": "twg_read",
        "title": "twg (read-only)",
        "description": "Run a read-only twg (Atlassian Teamwork Graph CLI) command: "
        "search and read Jira, Confluence, JSM, Assets, Goals, Projects, Teams, Loom, "
        "Trello, Rovo search, code search, people, org and work context. Nothing it "
        "runs changes data. Allowed top-level commands: %s. Only the read-only "
        "subcommands of each are allowed; the server instructions list them all. "
        "Bitbucket is handled by the separate `bb` connector, not by twg."
        % ", ".join(READ_TOPS),
        "inputSchema": MCP_TOOL_INPUT_SCHEMA,
        "annotations": {"title": "twg (read-only)", "readOnlyHint": True},
    },
    {
        "name": "twg_write",
        "title": "twg (makes changes)",
        "description": "Run a twg (Atlassian Teamwork Graph CLI) command that changes "
        "data: create, update, comment on, transition, link, log work on, archive or "
        "delete Jira work items, Confluence content, JSM records, Assets objects, "
        "goals, projects, teams, Loom videos and Trello cards. Allowed top-level "
        "commands: %s. Only the subcommands that change data are allowed; read-only "
        "ones go to twg_read. Bitbucket is handled by the separate `bb` connector, "
        "not by twg." % ", ".join(WRITE_TOPS),
        "inputSchema": MCP_TOOL_INPUT_SCHEMA,
        "annotations": {
            "title": "twg (makes changes)",
            "readOnlyHint": False,
            "destructiveHint": True,
        },
    },
]

_MCP_SLOTS = threading.BoundedSemaphore(MCP_MAX_CONCURRENT)


# ---- classification ------------------------------------------------------
def resolve_path(argv):
    """The command path the leading words of argv name, aliases resolved.

    Walks words until the first option or the first word that does not extend
    a known command path, so what follows is positional to that command.
    """
    path = ()
    for word in argv:
        if word.startswith("-"):
            break
        word = ALIASES.get(path, {}).get(word, word)
        if path + (word,) not in KNOWN_PREFIXES:
            break
        path = path + (word,)
    return path


def classify_args(argv):
    """Returns {'kind': 'read'|'write'|'help'|'blocked'|'unknown', ...}."""
    if argv in (["--help"], ["-h"], ["--version"], ["-v"], ["-V"]):
        return {"kind": "help"}
    first = argv[0]
    if first.startswith("-"):
        return {
            "kind": "unknown",
            "reason": "put the command words first and global options after them, "
            'for example ["work", "query", "-o", "json"].',
        }
    for word in (first, ALIASES[()].get(first, first)):
        if word in REFUSED_FAMILIES:
            return {"kind": "blocked", "reason": "`twg %s` is refused: %s"
                    % (first, REFUSED_FAMILIES[word])}
    path = resolve_path(argv)
    if path in REFUSED_COMMANDS:
        return {"kind": "blocked", "reason": "`twg %s` is refused: %s."
                % (" ".join(path), REFUSED_COMMANDS[path])}
    for option in argv[len(path):]:
        name = option.split("=", 1)[0]
        if name in FILE_OPTIONS:
            return {
                "kind": "blocked",
                "reason": "%s names a file on the machine twg runs on. Pass the "
                "content inline instead (--body, --input-json, --variables-json)." % name,
            }
        if name in REFUSED_FLAGS.get(path, ()):
            return {"kind": "blocked", "reason": "`twg %s %s` is refused."
                    % (" ".join(path), name)}
    if path == ("api",):
        # Any argument, not just the first positional: -X POST would shift it.
        if any(a.lower().startswith(("http://", "https://", "//")) for a in argv[1:]):
            return {
                "kind": "blocked",
                "reason": "an absolute URL could send the Atlassian credentials to "
                "another host. Give a path such as /rest/api/3/myself.",
            }
    if path in READ_COMMANDS:
        return {"kind": "read", "path": path}
    if path in WRITE_COMMANDS:
        return {"kind": "write", "path": path}
    return {
        "kind": "unknown",
        "reason": "`twg %s` is not an allowed command. Run {\"args\": [\"help\", "
        "\"describe\", \"%s\"]} with twg_read to see what exists, then use a full "
        "command path such as jira workitem get."
        % (" ".join(argv[:4]), " ".join(path) or first),
    }


# ---- running a command ---------------------------------------------------
def redact(text, secret=None):
    """Remove anything that looks like a credential. Runs before capping."""
    if not text:
        return text
    if secret:
        text = text.replace(secret, "[REDACTED]")
    for pattern in TOKEN_PATTERNS:
        if pattern.groups >= 2:
            text = pattern.sub(lambda m: m.group(1) + "[REDACTED]", text)
        else:
            text = pattern.sub("[REDACTED]", text)
    return text


def cap(data):
    """Cap combined output at MCP_MAX_OUTPUT bytes, with a clear marker."""
    if len(data) <= MCP_MAX_OUTPUT:
        return data.decode("utf-8", "replace")
    head = data[:MCP_MAX_OUTPUT].decode("utf-8", "ignore")
    return head + (
        "\n\n[TRUNCATED: output cut after %d of %d bytes. Ask for less: add --limit, "
        "--select, or narrower filters.]" % (MCP_MAX_OUTPUT, len(data))
    )


def run_twg(argv, timeout=MCP_COMMAND_TIMEOUT):
    """Run twg in its own process group, never through a shell.

    Returns (code, combined_output_bytes); code is None on timeout.
    """
    proc = subprocess.Popen(
        [TWG_BIN] + list(argv),
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=dict(TWG_ENV),
        cwd=TWG_HOME,
        start_new_session=True,
    )
    try:
        output, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            proc.kill()
        try:
            output, _ = proc.communicate(timeout=10)
        except Exception:
            output = b""
        return None, output or b""
    return proc.returncode, output


# ---- JSON-RPC ------------------------------------------------------------
def tool_result(text, is_error=False):
    return {"content": [{"type": "text", "text": text}], "isError": bool(is_error)}


def rpc_response(msg_id, result=None, error=None):
    reply = {"jsonrpc": "2.0", "id": msg_id}
    if error is not None:
        reply["error"] = error
    else:
        reply["result"] = result
    return reply


def rpc_error(code, message):
    return {"code": code, "message": message}


def tools_call(params, state, log):
    """tools/call. Only an unknown tool or malformed params is a protocol error."""
    if not isinstance(params, dict):
        return rpc_error(-32602, "params must be an object"), None
    name = params.get("name")
    if not isinstance(name, str):
        return rpc_error(-32602, "tools/call needs a string name"), None
    arguments = params.get("arguments")
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict):
        return rpc_error(-32602, "arguments must be an object"), None
    if name not in ("twg_read", "twg_write"):
        return rpc_error(-32602, "unknown tool: %s" % name), None

    log["tool"] = name
    argv = arguments.get("args")
    if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
        return None, tool_result(
            'args must be an array of strings, for example {"args": ["work", "query"]}.',
            True,
        )
    if not argv:
        return None, tool_result(
            'args is empty. Give the words that follow twg, for example '
            '{"args": ["work", "query"]}.',
            True,
        )
    if any("\x00" in item for item in argv):
        return None, tool_result("args may not contain NUL characters.", True)

    verdict = classify_args(argv)
    kind = verdict["kind"]
    log["args"] = " ".join(verdict.get("path") or argv[:1])
    log["kind"] = kind

    if kind in ("blocked", "unknown"):
        return None, tool_result("Refused: " + verdict["reason"], True)
    if kind == "read" and name == "twg_write":
        return None, tool_result(
            "Refused: `twg %s` is read-only. Call it with twg_read instead."
            % " ".join(verdict["path"]),
            True,
        )
    if kind == "write" and name == "twg_read":
        return None, tool_result(
            "Refused: `twg %s` changes data, so twg_read will not run it. Use "
            "twg_write instead." % " ".join(verdict["path"]),
            True,
        )

    if not _MCP_SLOTS.acquire(blocking=False):
        return None, tool_result("busy, retry shortly", True)
    try:
        code, output = run_twg(argv)
    finally:
        _MCP_SLOTS.release()

    text = redact(output.decode("utf-8", "replace"), state.get("secret"))
    text = cap(text.encode("utf-8"))
    if code is None:
        log["exit"] = "timeout"
        return None, tool_result(
            text + "\n\n[timed out after %d seconds; twg was killed]" % MCP_COMMAND_TIMEOUT,
            True,
        )
    log["exit"] = code
    return None, tool_result("%s\n\n[exit code: %d]" % (text.rstrip("\n"), code), code != 0)


def handle_message(msg, state, log):
    """One JSON-RPC message in, one reply out (or None for a notification)."""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        return rpc_response(None, error=rpc_error(-32600, "invalid request"))
    method = msg.get("method")
    has_id = "id" in msg
    msg_id = msg.get("id")

    if not isinstance(method, str):
        if has_id and ("result" in msg or "error" in msg):
            return None
        return rpc_response(msg_id, error=rpc_error(-32600, "invalid request"))

    log["method"] = method
    params = msg.get("params")

    if method == "initialize":
        requested = None
        if isinstance(params, dict):
            requested = params.get("protocolVersion")
            client = params.get("clientInfo")
            if isinstance(client, dict):
                log["client_name"] = client.get("name")
                log["client_version"] = client.get("version")
        log["asked_version"] = requested
        version = requested if requested in MCP_VERSIONS else MCP_NEWEST
        result = {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "twg", "version": __version__},
            "instructions": MCP_INSTRUCTIONS,
        }
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": MCP_TOOLS}
    elif method == "prompts/list":
        result = {"prompts": []}
    elif method == "resources/list":
        result = {"resources": []}
    elif method == "resources/templates/list":
        result = {"resourceTemplates": []}
    elif method == "tools/call":
        error, result = tools_call(params, state, log)
        if error is not None:
            return rpc_response(msg_id, error=error) if has_id else None
    else:
        if not has_id:
            return None
        return rpc_response(msg_id, error=rpc_error(-32601, "method not found: %s" % method))

    if not has_id:
        return None
    return rpc_response(msg_id, result=result)


# ---- failed-secret tracking ---------------------------------------------
class FailTracker(object):
    """Counts wrong secrets per client and locks that client out for a while."""

    def __init__(self):
        self._lock = threading.Lock()
        self._failures = {}
        self._locked_until = {}

    def record_failure(self, client, now):
        with self._lock:
            recent = [t for t in self._failures.get(client, []) if now - t < MCP_FAIL_WINDOW]
            recent.append(now)
            self._failures[client] = recent
            if len(recent) > MCP_FAIL_LIMIT:
                self._locked_until[client] = now + MCP_LOCKOUT
                return True
            return self._locked_until.get(client, 0.0) > now

    def clear(self, client):
        with self._lock:
            self._failures.pop(client, None)
            self._locked_until.pop(client, None)


# ---- logging (never arguments beyond the command path, never output) ----
def log_value(value):
    text = "".join(ch for ch in str(value) if ch >= " " and ch != "\x7f")
    if len(text) > 200:
        text = text[:200]
    if text == "" or " " in text or '"' in text or "=" in text:
        text = '"%s"' % text.replace('"', "'")
    return text


def log_line(fields):
    parts = ["%s=%s" % (key, log_value(value)) for key, value in fields.items()
             if value is not None and value != ""]
    sys.stderr.write(" ".join(parts) + "\n")
    sys.stderr.flush()


# ---- the HTTP surface ----------------------------------------------------
class _TooBig(Exception):
    pass


class _BadBody(Exception):
    pass


class McpHandler(http.server.BaseHTTPRequestHandler):
    # HTTP/1.0 on purpose: every response closes the connection.
    server_version = "twg-mcp"
    sys_version = ""
    timeout = MCP_SOCKET_TIMEOUT

    def log_message(self, fmt, *a):
        return

    def _state(self):
        return self.server.twg_state

    def _client(self):
        forwarded = self.headers.get("CF-Connecting-IP")
        if forwarded and forwarded.strip():
            return forwarded.strip()[:200]
        return self.client_address[0] if self.client_address else "?"

    def _reply(self, status, payload=None, headers=None):
        body = b""
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        if payload is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)
        return status

    def _host_ok(self):
        host = (self.headers.get("Host") or "").strip()
        port = self.server.server_address[1]
        allowed = set(MCP_TUNNEL_HOSTS)
        allowed.add("127.0.0.1:%d" % port)
        allowed.add("localhost:%d" % port)
        return host in allowed, host

    def _declared_too_big(self):
        raw = self.headers.get("Content-Length")
        if raw is None:
            return False
        try:
            return int(raw) > MCP_MAX_BODY
        except (TypeError, ValueError):
            return False

    def _secret_ok(self):
        offered = self.headers.get("Authorization") or ""
        expected = "Bearer " + self._state()["secret"]
        return hmac.compare_digest(offered.encode("utf-8", "replace"),
                                   expected.encode("utf-8"))

    def _read_body(self):
        encoding = (self.headers.get("Transfer-Encoding") or "").lower()
        if "chunked" in encoding:
            return self._read_chunked(), "chunked"
        raw = self.headers.get("Content-Length")
        if raw is None:
            return b"", "none"
        try:
            length = int(raw)
        except (TypeError, ValueError):
            raise _BadBody()
        if length > MCP_MAX_BODY:
            raise _TooBig()
        if length <= 0:
            return b"", "content-length 0"
        return self.rfile.read(length), "content-length %d" % length

    def _read_chunked(self):
        pieces = []
        total = 0
        while True:
            line = self.rfile.readline(65536)
            if not line:
                raise _BadBody()
            head = line.strip().split(b";")[0]
            try:
                size = int(head, 16)
            except ValueError:
                raise _BadBody()
            if size < 0:
                raise _BadBody()
            if size == 0:
                while True:
                    trailer = self.rfile.readline(65536)
                    if not trailer or trailer in (b"\r\n", b"\n"):
                        break
                break
            total += size
            if total > MCP_MAX_BODY:
                raise _TooBig()
            pieces.append(self.rfile.read(size))
            self.rfile.read(2)
        return b"".join(pieces)

    def do_POST(self):
        self._serve("POST")

    def do_GET(self):
        self._serve("GET")

    def do_DELETE(self):
        self._serve("DELETE")

    def do_HEAD(self):
        self._serve("HEAD")

    def do_OPTIONS(self):
        self._serve("OPTIONS")

    def _serve(self, verb):
        started = time.time()
        origin = self.headers.get("Origin")
        log = {
            "time": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "client": self._client(),
            "verb": verb,
            "path": self.path,
            "origin": origin if origin is not None else "-",
            "ua": self.headers.get("User-Agent") or "-",
        }
        if origin is None or origin.rstrip("/") not in MCP_KNOWN_ORIGINS:
            log["origin_unknown"] = "yes"
        try:
            status = self._route(verb, log)
        except Exception as exc:  # never leak a traceback
            log["error"] = type(exc).__name__
            try:
                status = self._reply(500, {"error": "internal error"})
            except Exception:
                status = 500
        log["status"] = status
        log["ms"] = int((time.time() - started) * 1000)
        ordered = {}
        for key in ("time", "client", "status", "verb", "path", "method", "tool",
                    "args", "kind", "exit", "ms", "origin", "origin_unknown", "ua",
                    "host", "body", "asked_version", "client_name", "client_version",
                    "error"):
            if key in log:
                ordered[key] = log[key]
        log_line(ordered)

    def _route(self, verb, log):
        path = urllib.parse.urlsplit(self.path).path

        host_ok, host = self._host_ok()
        if not host_ok:
            log["host"] = host or "-"
            return self._reply(421, {"error": "misdirected request"})

        # /.well-known/* answers without the secret, so claude.ai does not
        # mistake this for an OAuth-protected server.
        if path.startswith("/.well-known/") or path == "/.well-known":
            return self._reply(404, {"error": "not found"})

        if self._declared_too_big():
            return self._reply(413, {"error": "request too large"})

        state = self._state()
        client = self._client()
        now = time.time()
        if not self._secret_ok():
            locked = state["tracker"].record_failure(client, now)
            if locked:
                return self._reply(429, {"error": "too many attempts"},
                                   {"Retry-After": str(int(MCP_LOCKOUT))})
            return self._reply(401, {"error": "unauthorized"})
        state["tracker"].clear(client)

        if path != "/mcp":
            return self._reply(404, {"error": "not found"})

        if verb != "POST":
            return self._reply(405, {"error": "method not allowed"}, {"Allow": "POST"})

        try:
            raw, framing = self._read_body()
        except _TooBig:
            return self._reply(413, {"error": "request too large"})
        except _BadBody:
            return self._reply(400, rpc_response(None, error=rpc_error(-32700, "could not read the body")))
        log["body"] = framing

        if not raw.strip():
            return self._reply(400, rpc_response(None, error=rpc_error(-32700, "empty body")))
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return self._reply(400, rpc_response(None, error=rpc_error(-32700, "parse error")))

        batched = isinstance(payload, list)
        messages = payload if batched else [payload]
        if batched and not messages:
            return self._reply(400, rpc_response(None, error=rpc_error(-32600, "invalid request")))

        replies = []
        for message in messages:
            reply = handle_message(message, state, log)
            if reply is not None:
                replies.append(reply)

        if not replies:
            return self._reply(202)

        bad = any((reply.get("error") or {}).get("code") in (-32700, -32600) for reply in replies)
        body = replies if batched else replies[0]
        return self._reply(400 if bad else 200, body)


# ---- the secret ----------------------------------------------------------
def write_secret(rotate):
    path = MCP_SECRET_PATH
    folder = os.path.dirname(path)
    if not os.path.isdir(folder):
        os.makedirs(folder, mode=0o700)
    os.chmod(folder, 0o700)
    if os.path.exists(path) and not rotate:
        print(path)
        return 0
    temporary = path + ".tmp"
    handle = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(handle, "w") as fh:
            fh.write(secrets.token_urlsafe(32) + "\n")
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    os.chmod(path, 0o600)
    print(path)
    if rotate:
        print("restart twg-mcp, then update the connector's header in claude.ai")
    return 0


def read_secret():
    path = MCP_SECRET_PATH
    if not os.path.exists(path):
        sys.exit("No secret yet. Run: twg-mcp --init-secret")
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode != 0o600:
        sys.exit("%s must be mode 600, but it is %o." % (path, mode))
    with open(path) as fh:
        secret = fh.read().strip()
    if not secret:
        sys.exit("The secret file is empty. Run: twg-mcp --rotate-secret")
    return secret


def make_server(port, secret):
    server = http.server.ThreadingHTTPServer((MCP_BIND, port), McpHandler)
    server.daemon_threads = True
    server.twg_state = {"secret": secret, "tracker": FailTracker()}
    return server


def main(argv=None):
    parser = argparse.ArgumentParser(prog="twg-mcp", description="Atlassian Teamwork Graph CLI (twg) as an MCP server")
    parser.add_argument("--port", type=int, default=MCP_PORT)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--init-secret", action="store_true")
    group.add_argument("--rotate-secret", action="store_true")
    group.add_argument("--show-header", action="store_true")
    group.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    if args.init_secret:
        return write_secret(rotate=False)
    if args.rotate_secret:
        return write_secret(rotate=True)
    if args.show_header:
        if not sys.stdout.isatty():
            sys.stderr.write("--show-header prints a secret, so it only runs in a terminal.\n")
            return 2
        print("Bearer " + read_secret())
        return 0
    if args.check:
        overlap = READ_COMMANDS & WRITE_COMMANDS
        print("read %d, write %d, refused %d, overlap %d"
              % (len(READ_COMMANDS), len(WRITE_COMMANDS), len(REFUSED_COMMANDS), len(overlap)))
        return 1 if overlap else 0

    secret = read_secret()
    server = make_server(args.port, secret)
    log_line({"time": time.strftime("%Y-%m-%dT%H:%M:%S"), "event": "listening",
              "address": "%s:%d" % (MCP_BIND, args.port), "version": __version__,
              "read": len(READ_COMMANDS), "write": len(WRITE_COMMANDS)})
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
