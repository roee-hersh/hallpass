# Releasing the packages

One release version covers everything the repository ships:

| Package | Source | Where users get it |
|---|---|---|
| `toolpass` (Python: the engine, the client, the `toolpass` command) | [`toolpass-py`](.) | [PyPI](https://pypi.org/project/toolpass/) |
| `toolpass-client` (Node and TypeScript client) | [`toolpass-ts`](../toolpass-ts) | [npm](https://www.npmjs.com/package/toolpass-client) |
| The server image | [`Dockerfile`](../Dockerfile), which installs `toolpass[crypto]` | `ghcr.io/roee-hersh/toolpass` |
| The Helm chart | [`deploy/helm/toolpass`](../deploy/helm/toolpass) | `oci://ghcr.io/roee-hersh/charts/toolpass` |

Each version in the repository is `0.0.0` (the chart's appVersion is `latest`, so a chart
installed from a clone runs the latest published image). The `release` workflow (`.github/workflows/release.yaml`,
started by hand or by `daily-release`) tags `main` and sets the version from the tag everywhere:
`.github/scripts/build-python.sh` writes it into `src/toolpass/_version.py`; the image, the chart
(version and appVersion) and the npm package get it too. The release skill
(`.claude/skills/release/SKILL.md`) lists what to check afterwards.

## Release assets

The `assets` job attaches a registry-free copy of the packages to the GitHub release, under fixed
names so `releases/latest/download/...` works:

| Asset | What it is |
|---|---|
| `toolpass-python.tar.gz` | The `toolpass` source distribution |
| `toolpass-<version>-py3-none-any.whl` | The `toolpass` wheel |
| `toolpass-client-node.tgz` | The npm package, as `npm pack` makes it |
| `checksums.txt` | SHA-256 of each of the above |

## Publishing to PyPI and npm

The `pypi` job publishes `toolpass`, and the `npm` job publishes
`toolpass-ts` as `toolpass-client`, with trusted publishing (OpenID Connect), so no long-lived
token is stored. The jobs run only while the Actions variables `PUBLISH_PYPI` and `PUBLISH_NPM` are
`true`; unset, they are skipped and the release still succeeds, so the release skill checks the
registries after every release.

**PyPI.** `toolpass` needs a trusted publisher. On pypi.org, under Your account → Publishing, add a
pending publisher (the project does not exist yet): project `toolpass`, owner `roee-hersh`,
repository `toolpass`, workflow `release.yaml`, environment `pypi`. The first release that runs
the `pypi` job creates the project. `PUBLISH_PYPI` must be `true`.

**npm.** npm can only configure trusted publishing for a package that exists, so:

1. Publish the first version of `toolpass-client` by hand from a release's
   `toolpass-client-node.tgz`: `npm publish toolpass-client-node.tgz --access public --otp=<code>`
   (the account needs two-factor authentication). Until then, the release's `npm` job finds no
   `toolpass-client` on npm and skips, with a note in the run's summary.
2. On npmjs.com, `toolpass-client` → Settings → Trusted publishing: GitHub Actions, owner
   `roee-hersh`, repository `toolpass`, workflow `release.yaml`, environment `npm`.
3. Set the Actions variable `PUBLISH_NPM` to `true`. The workflow authenticates with its OpenID
   Connect token.
