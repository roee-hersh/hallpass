"""hallpass as a Strands Agents intervention handler: ``hallpass.strands``.

    pip install "hallpass-client[strands]"   # or: pip install "hallpass[strands]"

    from hallpass_client import Hallpass
    from hallpass_client.strands import HallpassAuthorization, Rule
"""

from hallpass.strands import HallpassAuthorization, Rule

__all__ = ["HallpassAuthorization", "Rule"]
