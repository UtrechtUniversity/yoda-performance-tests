#!/usr/bin/env python3
__license__ = 'GPLv3, see LICENSE'

import argparse
import json
import pathlib
from typing import Any
import logging
import time
import os
import re
import gevent
from locust.runners import (
    LocalRunner,
    MasterRunner,
    STATE_CLEANUP,
    STATE_STOPPED,
    STATE_STOPPING,
)
from locust import LoadTestShape
from locust import events
logger = logging.getLogger(__name__)


# Precompiled regex patterns
CSRF_TOKEN_PATTERN = re.compile(r"tokenValue: '([a-zA-Z0-9._-]*)'")
USERS_PER_STEP = int(os.getenv("USERS_PER_STEP", "1"))
STEP_DURATION_SECONDS = int(os.getenv("STEP_DURATION_SECONDS", "30"))
SPAWN_RATE = float(os.getenv("SPAWN_RATE", "2"))
MAX_USERS = int(os.getenv("MAX_USERS", "200"))

# Breaking-point definitions.
MAX_P95_MS = int(os.getenv("MAX_P95_MS", "5000"))
# MAX_P95_MS = int(os.getenv("MAX_P95_MS", "2000"))
MAX_AVERAGE_MS = int(os.getenv("MAX_AVERAGE_MS", "3000"))
MAX_FAILURE_RATIO = float(os.getenv("MAX_FAILURE_RATIO", "0.05"))
NO_PROGRESS_SECONDS = 30

# Avoid stopping because of unstable statistics during the first few requests.
MIN_REQUESTS_BEFORE_CHECK = int(
    os.getenv("MIN_REQUESTS_BEFORE_CHECK", "50")
)

# A threshold must remain violated for several checks before stopping.
CONSECUTIVE_BAD_CHECKS = int(
    os.getenv("CONSECUTIVE_BAD_CHECKS", "3")
)




def json_dict(path: str) -> Any:
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

class BreakingPointShape(LoadTestShape):
    """
    Increase the target user count every STEP_DURATION_SECONDS.

    Example:

        0-60 seconds:      5 users
        60-120 seconds:   10 users
        120-180 seconds:  15 users
        ...
    """

    def tick(self):
        run_time = self.get_run_time()

        step_number = int(run_time // STEP_DURATION_SECONDS) + 1
        target_users = step_number * USERS_PER_STEP

        if target_users > MAX_USERS:
            return None

        return target_users, SPAWN_RATE





# ---------------------------------------------------------------------------
# Stop when the system reaches its breaking point
# ---------------------------------------------------------------------------

def breaking_point_monitor(environment):
    consecutive_bad_checks = 0
    last_completed = 0
    last_progress_time = time.monotonic()
    response_count = 0
    response_period = 0
    while environment.runner.state not in {
        STATE_STOPPING,
        STATE_STOPPED,
        STATE_CLEANUP,
    }:
        gevent.sleep(5)
        response_period = time.monotonic() - last_progress_time
        stats = environment.runner.stats.total
        completed = stats.num_requests
        response_count = completed - last_completed
        last_completed = completed
        if response_count > 0:
            last_progress_time = time.monotonic()

        if response_period >= NO_PROGRESS_SECONDS and response_count == 0:
            logging.error(
                "Stopping: no requests completed for %.5f seconds",
                response_period,
            )
            print(
                f"Stopping: no requests completed for {response_period:.1f} seconds"
            )
            environment.runner.quit()
            return
        else:
            print(
                f"{response_count} queries completed in the last {response_period:.5f} seconds"
            )



        if stats.num_requests < MIN_REQUESTS_BEFORE_CHECK:
            continue

        p95_ms = stats.get_response_time_percentile(0.95)
        average_ms = stats.avg_response_time or 0
        failure_ratio = stats.fail_ratio

        current_users = environment.runner.user_count

        logger.info(
            "Health check: users=%s requests=%s "
            "p95=%.0fms average=%.0fms failure_ratio=%.2f%%",
            current_users,
            stats.num_requests,
            p95_ms,
            average_ms,
            failure_ratio * 100,
        )
        print(
            f"Health check: users={current_users} requests={stats.num_requests} "
            f"p95={p95_ms:.0f}ms average={average_ms:.0f}ms failure_ratio={failure_ratio * 100:.2f}%"
        )

        # # finish this time
        # environment.process_exit_code = 1
        # environment.runner.quit()
        # return

        reasons = []

        if p95_ms > MAX_P95_MS:
            reasons.append(
                f"p95 {p95_ms:.0f} ms > {MAX_P95_MS} ms"
            )

        if average_ms > MAX_AVERAGE_MS:
            reasons.append(
                f"average {average_ms:.0f} ms > "
                f"{MAX_AVERAGE_MS} ms"
            )

        if failure_ratio > MAX_FAILURE_RATIO:
            reasons.append(
                f"failure ratio {failure_ratio:.2%} > "
                f"{MAX_FAILURE_RATIO:.2%}"
            )

        if reasons:
            consecutive_bad_checks += 1

            logger.warning(
                "Threshold violation %s/%s at %s users: %s",
                consecutive_bad_checks,
                CONSECUTIVE_BAD_CHECKS,
                current_users,
                "; ".join(reasons),
            )
        else:
            consecutive_bad_checks = 0

        if consecutive_bad_checks >= CONSECUTIVE_BAD_CHECKS:
            logger.error(
                "BREAKING POINT reached at approximately %s users: %s",
                current_users,
                "; ".join(reasons),
            )

            # Non-zero exit code is useful in CI.
            environment.process_exit_code = 1
            environment.runner.quit()
            return


@events.init.add_listener
def start_breaking_point_monitor(environment, **kwargs):
    """
    Only monitor aggregate statistics on the local runner or master.
    Do not start a separate monitor on every distributed worker.
    """
    print("------------------------------------------------------------------------------------")
    print(f"Starting breaking point monitor for runner type: {type(environment.runner)}")
    if isinstance(environment.runner, (LocalRunner, MasterRunner)):
        gevent.spawn(breaking_point_monitor, environment)
    else:
        print("Not starting breaking point monitor on worker node")



@events.init_command_line_parser.add_listener
def _(parser: argparse.ArgumentParser) -> None:
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
def _(environment: Any, **kw: str) -> None:
    print(f"Custom argument supplied - environment: {environment.parsed_options.environment}")
    print(f"Custom argument supplied - user-credentials: {environment.parsed_options.user_credentials}")

@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    print("EVENT: test_stop")


@events.quitting.add_listener
def on_quitting(environment, **kwargs):
    print("EVENT: quitting")


@events.quit.add_listener
def on_quit(exit_code, **kwargs):
    print("EVENT: quit", exit_code)