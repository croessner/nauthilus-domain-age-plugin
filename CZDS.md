# ICANN CZDS collector

CZDS access requires an ICANN account and separate registry approval for each
zone. This collector intentionally supports only `com`, `net`, `org`, `info`,
`biz`, `xyz`, `top`, `online`, `site` and `shop`. It never requests additional
access or accepts agreements automatically. See [ICANN CZDS](https://czds.icann.org/help)
and the [official API example](https://github.com/icann/czds-api-client-python).

## Meaning of the evidence

A zone supplies delegations, not registration dates or historical global
first-seen data. The first accepted complete acquisition is a baseline. Its
domains remain unknown for external first-seen age. Only domains first
observed in later complete acquisitions acquire an observation timestamp.
History survives disappearance and reappearance. A gap in collection reduces
time resolution; the source is explicitly `czds-zone-observation`.

The plugin supplements only absent JSON `first_seen` evidence. A JSON
registration date does not suppress CZDS observations. Source acquisition
time controls freshness, independently of publication time. RDAP remains
responsible for optional registration evidence. Nauthilus Policy remains the
only decision authority; this feed never introduces a mail rejection.

## Private state and bounded publication

Run exactly one collector using a private persistent local filesystem. Do not
put the live SQLite history on a shared filesystem. The initialization command
is explicit; ordinary runs refuse to create a baseline after state loss.
Store backups must preserve `history.sqlite` and `initialized` together while
the collector is stopped (or use SQLite's online backup API). Never copy a
live database without its transactional consistency guarantees. Restore a
consistent backup on node replacement; keep acquisition disabled until then.

Each successful import commits history, acquisition metadata, original notices
and the acquisition timestamp in one transaction. Publication follows that
commit and is regenerated before another download after restart. Publication
uses file and parent-directory synchronization and atomic replacement.

Limits are 12 GiB per SQLite database, 40 GiB for the complete local state,
20 GiB minimum host-free reserve, 8 GiB compressed and 64 GiB decompressed per
zone, 64 KiB per line/notice capture, a six-hour run deadline, and bounded
SQLite caches. A local PV capacity field does not enforce these limits.
Allow peak space for history, stage and rollback journal together. Measure a
real baseline before enabling unattended collection; the limits are safety
ceilings, not a claim that every future zone will fit or finish in six hours.

Full history remains local. Only first observations from the last 90 days are
published, capped at ten million records across all zones (400 MB of records).
An overflow rejects publication and retains the previous generation; it never
silently truncates a claimed window. Omitted older observations are unknown to
the plugin. Use a separate 2 GiB publication volume and mount it read-only in
Nauthilus. Do not publish histories, indexes or zone files in GitHub releases.

The binary format has a 128-byte big-endian header (`>8sQQQ16s32s48s`): magic
`CZDSIDX1`, acquisition Unix time, baseline Unix time, record count, padded
ASCII zone, SHA-256 of the records, zeroed reserved bytes. Each sorted unique
record contains a 32-byte domain SHA-256 and an 8-byte first observation time.
Hashes are index keys, not a promise of anonymization. Treat the index as
private licensed data. Background validation checks integrity, ordering and
timestamps. Request lookups reopen only a matching validated file identity.
A process-wide four-slot I/O budget bounds stalled filesystem operations even
across plugin reloads; caller wait is limited to 100 ms. Missing, changed or
unavailable evidence remains unknown without blocking host shutdown.

## Operation

Set optional plugin configuration `czds_directory` to the publication directory
and restart Nauthilus for this service configuration change. Existing default
configuration remains valid without a collector.

Initialize a new explicitly approved state once:

```sh
python3 scripts/czds.py --state /state --output /publication --initialize
```

Mount existing account credentials as private `username` and `password` files
in `/credentials`. Use the operator's secret-management workflow. The RNS
enrollment helper accepts the existing password through a hidden terminal
prompt and writes only SOPS ciphertext; never paste credentials into chat.
The ICANN token stays in process memory. HTTPS destinations are fixed, proxies
and redirects are disabled, and neither response bodies nor credentials are
logged. Credentials are not needed for synthetic validation.

Review plausible minimum delegation counts for every zone before initial
acquisition. The example thresholds are safeguards to review, not current
registry statistics or proof of completeness. HTTP/gzip completion, SOA/NS
validation and a ten-percent maximum count decrease guard each import. An
unusual legitimate change needs investigation and a deliberate threshold or
validator update, rather than bypassing safeguards silently.

```sh
python3 scripts/czds.py --state /state --output /publication \
  --credentials /credentials --minimum-counts /config/minimum-counts.json
```

Persisted attempt timestamps enforce at least 24 hours between downloads of
the same zone, including interrupted or failed downloads. Schedule daily;
forbid overlapping jobs. Unapproved zones are logged as pending and skipped.
Authentication failures and failed imports exit unsuccessfully. Alert on job
failure, missing expected approvals, stale acquisition timestamps, state-budget
pressure or publication overflow. An expired approval must be renewed in CZDS;
the collector never renews agreements itself. A credential change requires
updating only the mounted Secret, not source code.

Test with `make test-collector`; the pinned collector image also runs these
tests during its build. Native tests run within the exact pinned Nauthilus
checkout through the normal plugin guardrails.
