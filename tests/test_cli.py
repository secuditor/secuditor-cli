import pytest

from secuditor_cli.cli import build_parser


@pytest.mark.parametrize(
    "command",
    [
        "domain",
        "endpoint",
        "apps",
        "lan",
        "network",
        "password",
        "remote",
        "server",
        "system",
    ],
)
def test_cli_accepts_audit_commands(command):
    args = build_parser().parse_args([command])
    assert args.command == command


def test_json_option():
    args = build_parser().parse_args(["endpoint", "--json"])
    assert args.json is True


def test_json_defaults_to_false():
    args = build_parser().parse_args(["domain"])
    assert args.json is False
