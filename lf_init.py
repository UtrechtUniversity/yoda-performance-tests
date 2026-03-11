#!/usr/bin/env python3
__license__ = 'GPLv3, see LICENSE'

import argparse
import json
import pathlib

from locust import events


def json_dict(path: str) -> dict:
    """
    Argparse “type” that reads *path*, parses it as JSON and returns a dict.

    Raises argparse.ArgumentTypeError on any problem so argparse will
    display a nice usage message.

    AI generated: internally hosted openai/gpt-oss-120b
    """
    p = pathlib.Path(path)
    if not p.is_file():
        raise argparse.ArgumentTypeError(f'File not found: {path!r}')
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError as exc:
        raise argparse.ArgumentTypeError(f'Invalid JSON in {path!r}: {exc}') from exc


@events.init_command_line_parser.add_listener
def _(parser):
    parser.add_argument(
        "--environment",
        type=json_dict,
        default="environments/development.json",
        include_in_web_ui=False,
        help="Config file"
    )
    parser.add_argument(
        "--user-credentials",
        type=json_dict,
        default="users.json",
        include_in_web_ui=False,
        help="File containing the different users"
    )


@events.test_start.add_listener
def _(environment, **kw):
    print(f"Custom argument supplied - environment: {environment.parsed_options.environment}")
    print(f"Custom argument supplied - user-credentials: {environment.parsed_options.user_credentials}")
