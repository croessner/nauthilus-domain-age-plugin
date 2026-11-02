# Nauthilus domain-age plugin

A native Go plugin for domain registration age, externally observed first-seen and local SMTP observation history. Nauthilus Policy owns all delivery decisions. The plugin does not classify a young domain as spam by itself.

## Evidence model

`domain_age.assessment` serves `mail/assess-sender-domain` and `mail/observe-sender-domain`. Input: the admitted string `resource.mail.sender_domain`. IDNA Lookup and the pinned Public Suffix List normalize subdomains to registrable domains. IP literals, public suffixes, malformed names and mailbox strings are rejected. Private suffix entries are deliberately not accepted as registry domains.

The independent outputs are under `plugin.domain_age.*`:

- `domain`: canonical registrable domain.
- `registration_state`, `registration_source`, `registration_age_seconds`, `registration_data_age_seconds`.
- `external_first_seen_state`, `external_first_seen_source`, `external_first_seen_age_seconds`, `external_data_age_seconds`.
- `data_age_seconds`, `data_stale`: import publication age, independent of source acquisition times.
- `tracking_state`, `local_first_seen_age_seconds`, `observations`, `observation_window_start_unix`, `observation_window_seconds`.

Absent ages remain absent. State values distinguish known/stale/unknown, unsupported RDAP suffix, not-found, rate-limited, busy, missing-or-invalid-date, unavailable and expired bootstrap routing. Stale import dates are not silently refreshed by republishing. A failed online lookup does not turn a stale date into a fresh date. External first-seen is sensor-specific, not proof of a domain's first existence. Registration is not the same as first DNS visibility or first mail activity. Re-registration can change registration age; imported records are replaced rather than unconditionally merged with older dates.

## Local data first

`examples/domains.json` documents the normalized JSON snapshot. Maximum decoded source file: 64 MiB. Each timestamp needs its own `*_checked_at` acquisition timestamp and `*_source`; do not substitute import time for source acquisition. Unknown fields, duplicate domains, malformed dates and future evidence are rejected. Only canonical registrable domains belong in the dataset. A complete snapshot replaces the previous database; preserve historical provider observations in your upstream maintained database.

Use the shared importer to validate and atomically install an internally maintained snapshot:

```sh
make import INPUT=/secure/download/domains.json OUTPUT=/var/lib/nauthilus/domain-age.json
```

Omit OUTPUT to validate only. The importer writes a private temporary file and renames it after validation and fsync. Trigger normal Nauthilus plugin reconfiguration after replacing the file. Reconfiguration atomically swaps a validated database; invalid replacements retain the previous generation. RDAP endpoint and tracking changes require restart. The reference fixture is dated example data, not a current feed.

CZDS requires an ICANN account and per-zone permissions: https://czds.icann.org/help . Zone differences establish observation, not registration dates. DomainTools NOD provides licensed external first observations and authenticated downloads: https://docs.domaintools.com/api/threat-feeds/newly-observed-domains/ . Upstream accounts, API credentials, license acceptance and format-specific conversion remain operator inputs. No paid-provider downloader is claimed or enabled. Never redistribute licensed feeds through the source repository.

## Optional RDAP fallback

RDAP registration events follow RFC 9083: https://www.rfc-editor.org/rfc/rfc9083.html . Obtain routing from https://data.iana.org/rdap/dns.json and configure only operator-reviewed HTTPS registry base URLs under `rdap`, keyed by final TLD. Supply `rdap_bootstrap_updated_at` (RFC3339); routing expires after 30 days. An empty map means fully offline operation. No registration or secret is needed for the protocol itself; registry access limits still apply.

Queries run only when registration evidence is absent or stale. Domain identity, object class, registration date, response status, future dates and duplicate registration events are validated. Redirects are disabled. Connections resolve and pin public IPs; private and special-use destinations are rejected. TLS certificate verification stays enabled. Request timeout is 1.5 seconds, response limit 1 MiB, positive TTL 24 hours, negative TTL one minute, global rate one query per second, at most one active network lookup, cache capacity 4096. Concurrent pressure reports busy instead of building an unbounded queue. Online caches are process-local and lost on restart. The imported external-first-seen signal is never synthesized from RDAP.

## Optional local observations

Enable `tracking` and the separate `mail/observe-sender-domain` target. Its schema requires a caller-owned `resource.mail.observation_id` of at most 128 bytes. Policy selects the synchronous `mail/record` obligation. Assessment reads history before recording; the current SMTP observation affects the next evaluation. Socketmap uses the untracked assessment target and must not select recording.

The host Redis facade executes an atomic script on keys sharing a domain hash tag. The local first observation is retained for 365 days without sliding expiry. Loss/expiry of that key loses historical coverage: the next observation starts a new observation era. Missing history is not a known zero age. Counts cover the indicated UTC clock hour, are deduplicated for 24 hours, and saturate at 10000 (`tracking_state=saturated` denotes a lower bound). Current-hour keys expire after two hours. Deduplication remains valid for 24 hours only; never replay an observation after that horizon. Retained per-observation keys require Redis memory capacity and quotas appropriate to accepted ingress volume. These are SMTP observations, not delivered-message counts; sender identities are spoofable. Redis outages produce explicit unavailable state or fail the mandatory recording obligation.

## Postfix

See `examples/pfxhttp.yml` and `examples/postfix.cf`. The pfxhttp `decision.enabled` option selects the generic endpoint `/api/v1/policy/decisions` for either transport. Policy mode forwards envelope sender domain, SMTP client IP, protocol state and instance as admitted typed facts. It emits an observation identity only with explicit `observation_scope`, END-OF-MESSAGE state, instance and queue ID. Use a globally distinct scope per MTA; do not change it during retries. No recipient participates in deduplication.

`permit` and `not_applicable` map to DUNNO, `deny` to REJECT, indeterminate/protocol/network failures to DEFER_IF_PERMIT. Generic mode bypasses legacy response-cache fallback. Gzip is bounded after decompression. Responses require matching request identity, mandatory status fields and no return-only obligations. Backend response text never becomes a Postfix command. A null sender is neutral. Socketmap keys can be an envelope address or a domain, and return an access-map action; they carry no SMTP peer, headers or message identity.

Use check_policy_service for envelope context. Keep relay restrictions and reject_unauth_destination independent of this check. FILTER routes to a transport; it is not an HTTP lookup directive. Header From needs a header-aware Milter/content integration and is not available from this policy bridge. No component treats an envelope domain as authenticated identity.

## Policy and composition

`examples/policy.json` is a JSON Nauthilus configuration fragment (also valid YAML). Merge it by namespace/target identity with the module fragment. It contains caller admission, exact schemas, native bindings, domain plan, observation effect and rules. Replace the credential placeholder through the normal secret configuration path. The example seven-day registration rejection threshold is illustrative and should first be calibrated on production observations.

Add rules requiring `tracking_state=known`, a small `local_first_seen_age_seconds`, and a high `observations` count to detect previously quiet domains becoming active. The exact UTC window is exposed; a new clock hour resets its count. Combine external first-seen only when its state is known and acquisition age is acceptable. Do not infer safety from missing facts.

GeoIP can bind `environment.mail.client_ip` using its existing generic `decision_bindings`; reputation can bind `resource.mail.sender_domain` as `dns_domain` and the admitted peer as `ip`. Configure exact `mail/plugin.geoip.<component>` and `mail/plugin.reputation.<component>` provider ownership, schemas, scheduling and dependencies using the core examples. Do not activate peer-dependent rules for socketmaps. Reuse reputation's existing observation model rather than conflating its history with local first mail visibility. Optional cross-plugin deployment configuration remains site-specific.

## Build and release

No independent go.mod: Go plugins require the exact host dependency/package identity. The adapted Makefile builds inside a clean core checkout at the pinned CORE_REF, Go 1.27.3, netgo, runtimesecret and vendor mode. External-only packages from already-pinned modules are included during build. Use `make guardrails`, then `make build` before release. The Linux builder verifies both metadata and shared-package ABI against the unmodified host. Rebuild for each host release. Signing is opt-in with an explicit SIGNING_KEY; no inherited personal key path. Artifact images carry the signed shared object, checksum and provenance. Public source may be hosted on GitHub; credentials, provider data, build directories and signing keys must remain private.

Roll back by disabling the module/provider activation and restoring the previous compatible signed artifact plus its configuration. Removing/replacing Go shared objects requires a process restart. Changes to the maintained data snapshot can be rolled back by atomic import and reconfiguration.

Licensed under GPL-3.0-or-later.
