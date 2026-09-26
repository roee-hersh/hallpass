# Compatibility packages

`hallpass-client` used to be the Python client of a hallpass service, in `sdk/python`. The engine
is now the Python package `hallpass` ([`hallpass-py`](..)), which runs in-process or as the server
and includes the client (`Hallpass.remote`). So `hallpass-client` is now a small package that
depends on `hallpass` at the same version and re-exports it, for code written against the old
name:

| Directory | Package | What it is |
|---|---|---|
| [`hallpass-client`](hallpass-client) | `hallpass-client` on PyPI | `hallpass_client`: `Hallpass()` is `hallpass.Hallpass.remote()`; `guarded`, `current`, `Decision`, `PermissionDenied`, `ALLOW`, `DENY`, `UNKNOWN` are hallpass's own; `hallpass_client.strands` is `hallpass.strands` |

Existing code keeps working unchanged:

```python
from hallpass_client import Hallpass, guarded   # as before: a client of a hallpass server

hp = Hallpass()  # HALLPASS_URL and HALLPASS_API_KEY from the environment
```

New code should depend on `hallpass` and write `Hallpass.remote(...)`, or run the engine in-process
with `Hallpass.from_config(...)`. `hallpass-client` now needs Python 3.10 or later, as `hallpass`
does. Its tests (`hallpass-client/tests`) check the re-exports against the installed packages.

The Node package of the same name, `hallpass-client` on npm, is unchanged: it is the client of a
hallpass server, and its source moved from `sdk/node` to [`hallpass-ts`](../../hallpass-ts).

## Releasing

Its version in the repository is `0.0.0`, and it depends on `hallpass==0.0.0`. The release
workflow's `.github/scripts/build-python.sh` sets both to the release version and builds it next to
`hallpass`, so the two are always released together at the same version. See
[RELEASING.md](../RELEASING.md).
