# Explorer API — run your own explorer

Any node can serve read-only chain data over local HTTP for a website, an
exchange integration, or scripts — plus a client-signed `POST /explorer/submit-tx`
endpoint for broadcasting transactions. It is **off by default** and costs nothing
when disabled: no thread, no socket. Your node syncs and verifies the chain
itself (proof of work, the signed network tip, frontier signature checks), so
everything this API serves is data **your** machine validated — you do not have
to trust anyone else's explorer, including ours.

## Enable it

```
ALPHANUMERIC_EXPLORER_API=127.0.0.1:8790 ALPHANUMERIC_HEADLESS=true ./alphanumeric
```

A bare port works too (`ALPHANUMERIC_EXPLORER_API=8790` binds 127.0.0.1). The
node needs no other configuration — it bootstraps to the canonical chain on
first start and keeps itself synced.

## Endpoints

All responses are JSON. Amounts appear twice: human units (`amount`) and exact
base units as a string (`amount_units`) so JavaScript never loses precision.

| Endpoint | Returns |
|---|---|
| `GET /explorer/status` | node version, network id, height, history-index state, uptime |
| `GET /explorer/tip` | the current tip block, full transactions |
| `GET /explorer/block/{height}` | one block with its transactions and `confirmations` |
| `GET /explorer/tx/{height}/{position}` | one transaction plus its block hash and confirmations |
| `GET /explorer/address/{address}` | balance, whole-history totals, newest-first transactions (paged) |
| `GET /explorer/supply` | circulating supply (sum of confirmed balances) |
| `POST /explorer/submit-tx` | accept a client-signed transaction and broadcast it to the network |

`submit-tx` is the one write route and exists only on a node's own explorer API
(`ALPHANUMERIC_EXPLORER_API`). The public gateway proxies the `GET` read routes
only and does **not** expose `submit-tx`.

### Address paging

`/explorer/address/{addr}?limit=50` returns the newest transactions and, when
there are more, a `next` cursor. Pass it back to walk history:

```
/explorer/address/{addr}?limit=50&before_height=1234&before_pos=1
```

`limit` is capped at 200 per page.

### Deposit detection (exchanges)

Poll your deposit address; each entry has `height`. Confirmations for an entry
are `tip_height - height + 1`. Coins from `"coinbase": true` transactions
(mining rewards) mature after 100 confirmations; ordinary transfers are usually
treated as final well before that (the network's finality margin is 64 blocks).

## Deployment notes

- **Keep the API on localhost.** Put your web server (nginx, Caddy, your app)
  in front for TLS, caching, and rate limiting. Finalized blocks never change —
  cache `/explorer/block/*` aggressively; cache tip/address responses for a few
  seconds. Binding a non-loopback address is allowed but logged with a warning:
  the node serves unauthenticated chain data and is not meant to face the
  internet directly.
- **No custody, no server-side signing.** Read requests never write to the
  database, trigger index rebuilds, or touch wallet keys. The one write path,
  `POST /explorer/submit-tx`, only accepts an already-signed transaction and
  relays it — the node never spends or sees a private key. A busy chain lock
  returns `503 {"error":"chain busy, retry shortly"}` rather than queueing work.
- **`index_ready: false`** in a response means the address-history index has
  not finished its first build (it builds automatically at startup, normally in
  well under a second). Balances are still served.
- A small VPS is plenty, but provision disk for growth: the node is
  self-contained and the on-disk database is on the order of ~700MB-1GB and
  grows with chain height (sled never shrinks). Run it under systemd/launchd so
  it restarts itself.
