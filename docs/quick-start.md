# Outrider quick start

Outrider is now web-first for human use. Install the web extra, start the local
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
