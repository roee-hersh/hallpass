# Releasing the packages

One release version covers everything the repository ships:

| Package | Source | Where users get it |
|---|---|---|
| `hallpass` (Python: the engine, the client, the `hallpass` command) | [`hallpass-py`](.) | [PyPI](https://pypi.org/project/hallpass/) |
| `hallpass-client` (Node and TypeScript client) | [`hallpass-ts`](../hallpass-ts) | [npm](https://www.npmjs.com/package/hallpass-client) |
| The server image | [`Dockerfile`](../Dockerfile), which installs `hallpass[crypto]` | `ghcr.io/roee-hersh/hallpass` |
| The Helm chart | [`deploy/helm/hallpass`](../deploy/helm/hallpass) | `oci://ghcr.io/roee-hersh/charts/hallpass` |

Each version in the repository is `0.0.0`. The `release` workflow (`.github/workflows/release.yaml`,
started by hand or by `daily-release`) tags `main` and sets the version from the tag everywhere:
`.github/scripts/build-python.sh` writes it into `src/hallpass/_version.py`; the image, the chart
(version and appVersion) and the npm package get it too. The release skill
(`.claude/skills/release/SKILL.md`) lists what to check afterwards.

## Release assets

The `assets` job attaches a registry-free copy of the packages to the GitHub release, under fixed
names so `releases/latest/download/...` works:

| Asset | What it is |
|---|---|
| `hallpass-python.tar.gz` | The `hallpass` source distribution |
| `hallpass-<version>-py3-none-any.whl` | The `hallpass` wheel |
| `hallpass-client-node.tgz` | The npm package, as `npm pack` makes it |
| `checksums.txt` | SHA-256 of each of the above |

## Publishing to PyPI and npm

The `pypi` job publishes `hallpass`, and the `npm` job publishes
`hallpass-ts` as `hallpass-client`, with trusted publishing (OpenID Connect), so no long-lived
token is stored. The jobs run only while the Actions variables `PUBLISH_PYPI` and `PUBLISH_NPM` are
`true`; unset, they are skipped and the release still succeeds, so the release skill checks the
registries after every release.

**PyPI.** `hallpass` needs a trusted publisher: on pypi.org, under Your projects → Publishing (or,
for a project that does not exist yet, a pending publisher), owner `roee-hersh`, repository
`hallpass`, workflow `release.yaml`, environment `pypi`. Then set the Actions variable
`PUBLISH_PYPI` to `true`. `hallpass-client` on PyPI, the old Python client, is no longer
published; `hallpass` replaces it.

**npm** (done).

1. npm can only configure trusted publishing for a package that exists, so the first version,
   0.4.0, was published by hand from the release's `hallpass-client-node.tgz`, with
   `npm publish hallpass-client-node.tgz --access public --otp=<code>` (the account needs
   two-factor authentication).
2. On npmjs.com, `hallpass-client` → Settings → Trusted publishing: GitHub Actions, owner
   `roee-hersh`, repository `hallpass`, workflow `release.yaml`, environment `npm`.
3. In the GitHub repository, set the Actions variable `PUBLISH_NPM` to `true`. The workflow
   authenticates with its OpenID Connect token.
