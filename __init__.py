"""Hermes plugin: Vaultwarden / Bitwarden Password Manager secret source.

Registers:
  * a ``vaultwarden`` :class:`SecretSource` (bulk) that pulls a vault
    item's custom fields via the ``bw`` CLI, and
  * the ``hermes vaultwarden setup|status|sync|disable`` CLI tree.

Install: symlink (or copy) this directory to ``~/.hermes/plugins/vaultwarden``
and add ``vaultwarden`` to ``plugins.enabled`` in ``~/.hermes/config.yaml``
(the setup wizard does the latter for you).
"""


def register(ctx):
    try:
        from . import vw_cli, vw_source
    except ImportError:  # loader without package context
        import vw_cli
        import vw_source

    ctx.register_secret_source(vw_source.VaultwardenSource())
    ctx.register_cli_command(
        name="vaultwarden",
        help="Vaultwarden / Bitwarden PM secret source (setup, status, sync, disable)",
        setup_fn=vw_cli.setup_parser,
        handler_fn=None,
        description=(
            "Pull env vars from a Vaultwarden vault item's custom fields "
            "via the bw CLI"
        ),
    )
