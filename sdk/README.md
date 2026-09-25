# Client SDKs

| Package | Directory | Install |
|---|---|---|
| Python | [`python`](python) | `pip install hallpass-client` ([PyPI](https://pypi.org/project/hallpass-client/)) |
| Node and TypeScript | [`node`](node) | `npm install hallpass-client` ([npm](https://www.npmjs.com/package/hallpass-client)) |

Both packages are named `hallpass-client`. They are thin clients of a running hallpass service:
`POST /check` and the `guarded` wrapper that puts the check in front of a tool. They follow the
same contract, and neither has runtime dependencies. One package per language covers every agent
framework; the framework examples are in [`examples/agent`](../examples/agent) and
[`examples/agent-ts`](../examples/agent-ts), and their tests are the client's behavioural tests.
The tests under each package check the built artifact.

## Releasing

Each package's version in the repository is `0.0.0`. The `release` workflow's `sdk` job sets it
from the release tag, builds both packages and attaches them to the GitHub release, so they always
carry the same version as the service:

| Asset | What it is |
|---|---|
| `hallpass-client-python.tar.gz` | The Python source distribution, under a fixed name so `releases/latest/download/...` works |
| `hallpass_client-<version>-py3-none-any.whl` | The Python wheel |
| `hallpass-client-node.tgz` | The npm package, as `npm pack` makes it |
| `sdk-checksums.txt` | SHA-256 of each of the above |

This needs no registry account.

### Publishing to PyPI and npm

The release workflow also publishes both packages to the registries as `hallpass-client`, with
trusted publishing, so no long-lived token is stored. Both registries are set up. The jobs run only
while the Actions variables `PUBLISH_PYPI` and `PUBLISH_NPM` are `true`; unset, they are skipped
and the release still succeeds, so the release skill checks the registries after every release.

How each registry was set up, for reference:

**PyPI** (done)

1. On pypi.org, under Your projects → Publishing, add a pending trusted publisher: project
   `hallpass-client`, owner `roee-hersh`, repository `hallpass`, workflow `release.yaml`,
   environment `pypi`.
2. In the GitHub repository, set the Actions variable `PUBLISH_PYPI` to `true`.

**npm** (done)

1. npm can only configure trusted publishing for a package that exists, so the first version,
   0.4.0, was published by hand from the release's `hallpass-client-node.tgz`, with
   `npm publish hallpass-client-node.tgz --access public --otp=<code>` (the account needs
   two-factor authentication).
2. On npmjs.com, `hallpass-client` → Settings → Trusted publishing: GitHub Actions, owner
   `roee-hersh`, repository `hallpass`, workflow `release.yaml`, environment `npm`.
3. In the GitHub repository, set the Actions variable `PUBLISH_NPM` to `true`. No token is
   stored; the workflow authenticates with its OpenID Connect token.
