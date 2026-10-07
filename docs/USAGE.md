# Usage baseline and weekly review

Collected at **2026-10-07 17:31 UTC** (2026-10-08 01:31 Asia/Shanghai).
This is an observed API snapshot, not a count of active users. Keep dates and
metric definitions with every future comparison.

## Observed baseline

| Metric | Returned period | Result | Interpretation |
|---|---|---:|---|
| GitHub page views | 2026-09-23–2026-10-06 UTC | 4 views / 2 unique visitors | Very little observed repository browsing; identity is unknown |
| GitHub full clones | Same period | 345 clones / 125 unique sources | Does not establish 125 people; automation and verification may contribute |
| npm downloads | 2026-10-03–2026-10-07 UTC, explicit daily range | 584 | Package fetches, not installations retained or active users; freshness caveat below |
| crates.io downloads | Lifetime count at collection | 44 | Downloads across versions, not distinct users |
| Confirmed external integrations | No verified ledger yet | Unknown | Downloads cannot fill this gap; external recruitment is deferred |
| One-week retained external integrations | No verified ledger yet | Unknown | Requires follow-up evidence from each integration |
| Website visits / search impressions | No verified analytics or Search Console data | Unknown | GitHub Traffic does not measure GitHub Pages visits or search rankings |

Daily returned values:

| UTC day | GitHub views / uniques | GitHub clones / uniques | npm downloads | crates.io downloads |
|---|---|---|---:|---:|
| 2026-10-03 | 1 / 1 | 169 / 44 | 308 | 28 |
| 2026-10-04 | 1 / 1 | 106 / 44 | 236 | 13 |
| 2026-10-05 | 2 / 1 | 52 / 35 | 40 | 3 |
| 2026-10-06 | 0 / 0 | 18 / 14 | 0* | No returned row |
| 2026-10-07 | Outside returned Traffic window | Outside returned Traffic window | 0* | No returned row |

**Freshness caveat:** npm's explicit range includes October 6–7 with zeros, but
its `last-day` endpoint still returns October 4 (236 downloads). Treat the latest
zeros as provisional, not proof that usage stopped. Do not combine differently
dated rolling endpoints into a trend. Missing crates.io rows are recorded as
missing, not assumed current-day zeros. Daily GitHub uniques must not be summed
to estimate window uniques; the API supplies the latter separately.

GitHub returned an empty referrer list. Popular paths were release editing
(2 views), the repository root (1) and the 0.1.3 release (1). This supports a
low-browsing conclusion, but does not identify who visited. Search engines and
GitHub itself are excluded from GitHub's referrer reporting; an empty list does
not establish absent search traffic. See [GitHub's Traffic documentation](https://docs.github.com/en/repositories/viewing-activity-and-data-for-your-repository/viewing-traffic-to-a-repository).

Evidence sources: authenticated GitHub Traffic endpoints below,
[npm explicit daily range](https://api.npmjs.org/downloads/range/2026-10-03:2026-10-07/keyspoor),
[npm last-day](https://api.npmjs.org/downloads/point/last-day/keyspoor),
[crates.io totals](https://crates.io/api/v1/crates/keyspoor) and
[crates.io daily downloads](https://crates.io/api/v1/crates/keyspoor/downloads).
The public endpoints are live and may subsequently change; the table records
what was returned at the collection time.

## Next review

Use a manual weekly check. No scanner telemetry or analytics service is added.
With GitHub CLI signed in to an account that can read repository Traffic:

```sh
gh api repos/majiayu000/keyspoor/traffic/views
gh api repos/majiayu000/keyspoor/traffic/clones
gh api repos/majiayu000/keyspoor/traffic/popular/referrers
gh api repos/majiayu000/keyspoor/traffic/popular/paths
```

Fetch the same npm explicit daily range for the comparison dates, and record
both its returned dates and the latest `last-day` date. Use crates.io version
and daily data to distinguish release downloads. GitHub's Traffic history is
short, so retain dated weekly summaries rather than expecting a later query to
recover an old window.

Review three separate questions:

1. **Discovery:** did comparable complete-day views, referrers or search
   impressions change? Do not claim an SEO lift from download counts.
2. **Activation:** did someone install and finish a real repository scan, hook,
   CI job or MCP call? Record version/platform, time to first success and a
   redacted success/failure result in the [feedback template](ADOPTION.md#feedback-to-collect).
3. **Retention and quality:** is that integration still running one week later,
   and were reported findings useful? Keep confirmed false positives, intentional
   fixtures and unresolved findings separate as in [the review](FINDING_REVIEW.md).

The future target remains five independently confirmed integrations and three
still running after a week. These are goals, not observed results. External
recruitment is deferred at the maintainer's request; existing launch drafts
remain available in [ADOPTION.md](ADOPTION.md#public-announcement-draft).
