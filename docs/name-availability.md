# Package/brand availability evidence (P0)

Checked 2026-09-13 (UTC) by live registry/GitHub queries. This records search
evidence only; it is not a legal clearance, trademark opinion, or guarantee of
future availability.

| Candidate | npm | npm `@latticeagi/` scoped | PyPI | GitHub `LatticeAG/` |
|---|---|---|---|---|
| Bedrock | taken (`bedrock@4.5.1`) | free | taken (`bedrock`) | free |
| CharterPin | free | free | free | free |
| RuleSeal | free | free | free | free |
| ScopeRock | free | free | free | free |
| PolicyLatch | free | free | free | free |

Method: `npm view <name>` / `npm view @latticeagi/<name>` against
registry.npmjs.org; `GET https://pypi.org/pypi/<name>/json`; unauthenticated
`GET https://github.com/LatticeAG/<repo>` (org page itself resolves).

Decision: the unqualified `bedrock` name is occupied on both package
registries, so the release names are scoped/explicit: `@latticeagi/bedrock`
(npm) and `latticeagi-bedrock` (PyPI). Wire prefixes (`bch_`, `bky_`, …) are
protocol constants independent of package names and are unchanged.
