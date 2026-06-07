# Watch the demo (20 seconds)

One command — `vigil-hub demo` — shows the whole idea: your AI agent tries to leak a
secret, and Vigils stops it. Everything below runs **locally**: the firewall, the
redaction, and the tamper-evident audit are the real runtime code paths; only the
external model/tool is simulated, and **no LLM is contacted**.

<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/asciinema-player@3.8.0/dist/bundle/asciinema-player.css" />
<div id="vigil-demo-player" style="max-width: 860px; margin: 1rem auto;"></div>
<script src="https://cdn.jsdelivr.net/npm/asciinema-player@3.8.0/dist/bundle/asciinema-player.min.js"></script>
<script>
  AsciinemaPlayer.create('./vigil-demo.cast', document.getElementById('vigil-demo-player'), {
    poster: 'npt:0:3',
    idleTimeLimit: 1.5,
    fit: 'width',
    theme: 'asciinema'
  });
</script>

> Player not loading? [Download the recording](./vigil-demo.cast) and play it with
> [`asciinema play vigil-demo.cast`](https://docs.asciinema.org/manual/cli/), or just run
> it yourself after [installing](./getting-started/installation.md): **`vigil-hub demo`**.

## What you just watched

1. **Default-deny.** The agent puts a *raw* GitHub token into a tool call. The firewall
   refuses to forward a raw secret — `DENY`.
2. **The Vigils way.** The agent instead passes a **placeholder** (`secret://github_pat`).
   The remote model only ever sees the placeholder; the real value is detokenized **only**
   at the local tool boundary; and when the tool's result leaks a credential back, Vigils
   re-redacts it before the model sees anything.
3. **Tamper-evident audit.** Every step lands in a SHA-256 hash-chained ledger — **with no
   plaintext secrets stored**. (`vigil-hub demo --tamper` alters one row and the chain
   verification fails, on purpose.)

The agent did useful work with a real secret — while the model, the logs, and the audit
**never received the real value**. That is the whole product, in one command.

Next: [install it](./getting-started/installation.md) and protect your own agents with
`vigil-hub setup --all`.
