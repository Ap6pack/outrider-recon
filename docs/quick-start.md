# Outrider quick start

## One command (recommended)

From a checkout, `bootstrap.sh` sets everything up and self-checks it:

```bash
git clone https://github.com/Ap6pack/outrider-recon.git
cd outrider-recon
./bootstrap.sh
source .venv/bin/activate
outrider
```

It creates an isolated `./.venv`, installs the package (web extra by default),
links the Claude skills from this checkout into `~/.claude/skills`, and runs the
deterministic benchmark self-check (no model, no network). A healthy run ends
with `promoted_findings_total: 0` and `schema_validity_rate: 1.0`. Flags:
`--no-web` (base install), `--no-skills` (skip skill linking), `--help`.

## Docker (Linux, browser only)

Outrider binds loopback only, so share the host loopback with `--network host`:

```bash
docker build -t outrider-recon .
docker run --rm --network host outrider-recon   # open http://127.0.0.1:8765
```

We deliberately do not bind `0.0.0.0`. On macOS/Windows Docker Desktop
`--network host` is limited; prefer `./bootstrap.sh` there.

## Manual

Outrider is web-first for human use. Install the web extra, start the local
portal, and complete the browser wizard before reviewing scope.

```bash
python -m pip install -e ".[web]"
outrider
```

The launcher creates `./runs` safely when it is missing, starts the portal on
`127.0.0.1:8765`, and opens your local browser. Use Outrider only for assets you
own or are authorized to assess.

## Browser wizard

1. Choose an engagement platform such as HackerOne, Bugcrowd, an internal
   assessment, a client engagement, or Other.
2. Enter the target, operator name, opaque authorization reference, and optional
   program traffic-identification header metadata.
3. Review exact in-scope and out-of-scope rules. The wildcard helper is optional;
   `*.example.com` does not include `example.com`.
4. Confirm authorization and create the engagement.
5. Select **Review Scope** as the first next action.

Discovery enrichment remains disabled unless explicitly enabled for the current
server session:

```bash
outrider --enable-mcp-enrichment
```

The stored traffic header is metadata only. Outrider does not automatically send
it to providers, perform discovery, change workflow state, create evidence,
execute skills, execute Claude, queue jobs, or generate reports during
onboarding.

## Advanced CLI

Existing CLI subcommands remain available for automation, recovery,
troubleshooting, CI, and advanced workflows. The explicit web command remains:

```bash
outrider web serve runs
```

After creating an engagement in the portal:

1. Review Scope.
2. Confirm Scope and Continue.
3. Begin Discovery.
4. Follow the next-action card.
