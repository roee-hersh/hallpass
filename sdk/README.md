# Client SDKs

| Package | Directory | Install |
|---|---|---|
| Python | [`python`](python) | `pip install https://github.com/roee-hersh/hallpass/releases/latest/download/hallpass-client-python.tar.gz` |
| Node and TypeScript | [`node`](node) | `npm install https://github.com/roee-hersh/hallpass/releases/download/v0.4.0/hallpass-client-node.tgz` |

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

### Publishing to PyPI and npm as well (optional)

The release workflow can also publish both packages to the registries as `hallpass-client`, with
trusted publishing, so no long-lived token is stored. It is off until set up once per registry;
until then, the names are not reserved, so do not point users at `pip install hallpass-client` or
`npm install hallpass-client`.

**PyPI**

1. On pypi.org, under Your projects → Publishing, add a pending trusted publisher: project
   `hallpass-client`, owner `roee-hersh`, repository `hallpass`, workflow `release.yaml`,
   environment `pypi`.
2. In the GitHub repository, set the Actions variable `PUBLISH_PYPI` to `true`.

**npm**

1. Create a granular access token on npmjs.com that can publish new packages, and store it as the
   Actions secret `NPM_TOKEN`. npm can only configure trusted publishing for a package that
   already exists, so the first publish needs the token.
2. Set the Actions variable `PUBLISH_NPM` to `true`.
3. After the first release, on npmjs.com open `hallpass-client` → Settings → Trusted publishing,
   add GitHub Actions with owner `roee-hersh`, repository `hallpass`, workflow `release.yaml`,
   environment `npm`, then delete the `NPM_TOKEN` secret.
