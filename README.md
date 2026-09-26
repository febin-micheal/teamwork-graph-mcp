# teamwork-graph-mcp

**MCP server for Atlassian Teamwork Graph**: Jira, Confluence, Jira Service Management, Assets, Goals, Projects, Teams, Loom, Trello, Rovo search, code search, people and org context, and the links between them, served from Atlassian's `twg` CLI to Claude (claude.ai, Claude Desktop, Claude Code, mobile) and other AI agents over the Model Context Protocol.

One standard-library Python file. It serves streamable HTTP on the loopback interface behind a bearer secret, and runs `twg` for each call against explicit allowlists.

## Features

Two tools. Each takes `{"args": [...]}`: the words that would follow `twg`, command first, global options (`-o json`, `--output-summary inline`, `--select …`) after them.

| Tool | What it runs |
|---|---|
| `twg_read` | Only commands on the read allowlist (313 commands): get, query, list, search and other non-mutating subcommands |
| `twg_write` | Only commands on the write allowlist (263 commands): create, update, delete, comment, transition, worklog, link/unlink, archive, approve, move, share, … |

Read allowlist, top-level commands: access, admin, artifacts, assets, capabilities, collaborators, commits, confluence, context, csm, deployments, docs, doctor, focus-areas, focus-areas-tree, goals, help, jira, jsm, loom, meetings, notifications, org-tree, people, pr-tree, projects, pull-requests, recently-viewed, resolve, responsibility, rovo, search-code, spaces, subgraph, talent, teams, trello, user, user-search, videos, whoami, work, work-tree, workitem-tree.

Write allowlist, top-level commands: admin, api, assets, confluence, goals, jira, jsm, loom, projects, teams, trello.

A read command sent to `twg_write`, a write command sent to `twg_read`, and anything on neither list are refused. `--help` works on any allowed command through the tool that would run it. The full lists are in the server's `initialize` instructions and in `READ_COMMANDS` / `WRITE_COMMANDS` in [server.py](src/teamwork_graph_mcp/server.py). They were generated from twg 1.3.1's help; anything a later twg adds stays refused until it is classified.

Refused by both tools:

- `bitbucket` / `bb` (use a separate Bitbucket server, such as bitbucket-mcp)
- `login`, `logout`, `auth …`, `admin auth …`, `rovo auth`, `env`, `setup …`, `update`/`upgrade`, `uninstall`, `upkeep …`, `consent`, `skills …`, `cache clear`, `completion`, `doctor --fix`
- `benchmark …`, `feedback`, `visualize`
- commands that move files between the server machine and Atlassian (attachment upload/download, `artifacts file create|update`, `loom video upload`)
- every option that names a local file (`--body-file`, `--input-file`, `--variables-file`, `--out`, …). Pass content inline instead (`--body`, `--input-json`, `--variables-json`)
- `api` with an absolute URL, so the credentials never go to another host

## Requirements

- Linux or macOS with Python 3.8 or newer (standard library only)
- Atlassian's Teamwork Graph CLI, `twg`, installed and signed in (follow Atlassian's instructions; check with `twg whoami`). It is an external requirement and is not included here.
- Optional: `cloudflared`, to reach the server from claude.ai and mobile

## Install

```sh
git clone <this repository's URL> teamwork-graph-mcp
cd teamwork-graph-mcp
pipx install .        # or: python3 -m pip install --user .
twg-mcp --check       # prints the allowlist sizes
```

## Configure

All settings are environment variables and all are optional. See [config.example.env](config.example.env).

| Variable | Default | Meaning |
|---|---|---|
| `TWG_MCP_BIND` | `127.0.0.1` | Address the server listens on. Keep it on the loopback interface |
| `TWG_MCP_PORT` | `8772` | Port the server listens on (`--port` overrides it) |
| `TWG_MCP_SECRET_FILE` | `~/.config/twg-mcp/mcp-secret` | File holding the bearer secret (mode 600) |
| `TWG_MCP_PUBLIC_HOSTS` | none | Comma-separated public host names that may reach the server, e.g. a tunnel hostname |
| `TWG_BIN` | `twg` on `TWG_PATH` | The twg binary |
| `TWG_HOME` | your home folder | `HOME` that twg runs with |
| `TWG_PATH` | `$TWG_HOME/.local/bin:/usr/local/bin:/usr/bin:/bin` | `PATH` that twg runs with |
| `TWG_CONFIG_DIR` | twg's default | Passed on to twg when set |
| `TWG_MCP_ACCOUNT_LABEL` | none | Account shown to the model ("signed in as …") |

## Run

```sh
twg-mcp --init-secret     # create the bearer secret (prints its path only)
twg-mcp                   # serve on 127.0.0.1:8772
twg-mcp --show-header     # print "Bearer …" (only when stdout is a terminal)
twg-mcp --rotate-secret   # replace the secret, then restart and update clients
```

As a systemd user service: copy [examples/teamwork-graph-mcp.service](examples/teamwork-graph-mcp.service) to `~/.config/systemd/user/`, set the path to `twg-mcp`, put your settings in `~/.config/twg-mcp/teamwork-graph-mcp.env`, then:

```sh
systemctl --user daemon-reload
systemctl --user enable --now teamwork-graph-mcp
journalctl --user -u teamwork-graph-mcp -f   # one line per request
```

The unit runs with `ProtectSystem=strict`; only `~/.config/twg` and `~/.cache/twg` are writable, because twg refreshes its OAuth token there.

## Connect to Claude

**claude.ai (web, desktop and mobile)**: Settings → Connectors → Add custom connector. URL `https://<your-public-host>/mcp`, and an `Authorization` header with the value from `twg-mcp --show-header`. claude.ai needs a public HTTPS URL; see the tunnel section below.

**Claude Code** on the same machine:

```sh
claude mcp add --transport http twg http://127.0.0.1:8772/mcp \
  --header "Authorization: Bearer $(cat ~/.config/twg-mcp/mcp-secret)"
```

## Optional: expose over Cloudflare Tunnel

```sh
cloudflared tunnel create <TUNNEL-NAME>
cloudflared tunnel route dns <TUNNEL-NAME> <MCP-HOSTNAME>
```

Use [examples/cloudflared.yml](examples/cloudflared.yml) as the tunnel config, set `TWG_MCP_PUBLIC_HOSTS=<MCP-HOSTNAME>`, and restart the service. The server itself still listens only on the loopback interface.

## Security notes

- Every request needs `Authorization: Bearer <secret>`, compared in constant time. A wrong secret gets `401`; more than 10 failures a minute from one client get `429` for 60 seconds.
- Requests whose `Host` is not `127.0.0.1:<port>`, `localhost:<port>` or a name in `TWG_MCP_PUBLIC_HOSTS` get `421`. `/.well-known/*` answers `404` without the secret, so clients do not look for OAuth.
- twg's credentials stay in twg's own config folder; the server never opens them.
- Output is scrubbed of the bearer secret and of anything shaped like a token (JWTs, Atlassian API tokens, `Bearer …`) before it is returned. The log records the tool, the command path and the exit code, never arguments or output.
- twg runs from an argument list (never a shell) with `TWG_AGENT_DEFAULTS=1`, stdin `/dev/null`, a 120-second timeout (the process group is killed) and combined output capped at 200 KB.
- `twg_read` only runs reads, so a client can auto-approve it and ask before `twg_write`.

## Credits

Written by Febin Micheal Antony. Built on Atlassian's Teamwork Graph CLI (`twg`), which is Atlassian's software and is not included here, and the [Model Context Protocol](https://modelcontextprotocol.io/).

## License

[MIT](LICENSE)
