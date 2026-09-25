# Client SDKs

| Package | Directory | Install |
|---|---|---|
| Python, `hallpass-client` on PyPI | [`python`](python) | `pip install hallpass-client` |
| Node and TypeScript, `hallpass-client` on npm | [`node`](node) | `npm install hallpass-client` |

Both are thin clients of a running hallpass service: `POST /check` and the `guarded` wrapper that
puts the check in front of a tool. They follow the same contract, and neither has runtime
dependencies. One package per language covers every agent framework; the framework examples are in
[`examples/agent`](../examples/agent) and [`examples/agent-ts`](../examples/agent-ts), and their
tests are the client's behavioural tests. The tests under each package check the built artifact.

## Releasing

Each package's version in the repository is `0.0.0`. The `release` workflow sets it from the
release tag and publishes both packages together with the binaries and the image, so the packages
always carry the same version as the service. Publishing uses trusted publishing (OpenID Connect
from GitHub Actions), so no long-lived registry token is stored.

Publishing is off until the maintainer sets it up once per registry:

**PyPI**

1. On pypi.org, under Your projects → Publishing, add a pending trusted publisher: project
   `hallpass-client`, owner `roee-hersh`, repository `hallpass`, workflow `release.yaml`,
   environment `pypi`.
2. In the GitHub repository, set the Actions variable `PUBLISH_PYPI` to `true`.

**npm**

1. Create an automation or granular access token on npmjs.com that can publish new packages, and
   store it as the Actions secret `NPM_TOKEN`. npm can only configure trusted publishing for a
   package that already exists, so the first publish needs the token.
2. Set the Actions variable `PUBLISH_NPM` to `true`.
3. After the first release, on npmjs.com open `hallpass-client` → Settings → Trusted publishing,
   add GitHub Actions with owner `roee-hersh`, repository `hallpass`, workflow `release.yaml`,
   environment `npm`, then delete the `NPM_TOKEN` secret.

The next release, daily or manual, then publishes both.
