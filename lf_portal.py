#!/usr/bin/env python3
__license__ = 'GPLv3, see LICENSE'

import json
import re
import tempfile
import os
from urllib import response
import gevent
import logging
import urllib3
import time
from locust import constant, HttpUser, task, tag,  LoadTestShape, between, events

from locust.runners import (
    LocalRunner,
    MasterRunner,
    STATE_CLEANUP,
    STATE_STOPPED,
    STATE_STOPPING,
)

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


class PortalBaseUser(HttpUser):
    # This class is meant to be subclassed, this is indicated by setting the class variable 'abstract' to True
    abstract = True
    wait_time = constant(1)
    host = "https://surf-yoda.irods.surfsara.nl"

def create_temp_binary_file(size_mb: int) -> str:
    # Calculate the size in bytes
    size_bytes = size_mb * 1024 * 1024
    # Create a temporary file
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        # Write zeros to the file to fill it to the desired size
        tmp.write(b'\0' * size_bytes)
        tmp_path = tmp.name
    return tmp_path

class PortalUser(PortalBaseUser):
    username: str = ""
    portal_csrf: str = ""
    portal_session_cookie: str = ""

    def on_start(self) -> None:
        env_config = self.environment.parsed_options.environment

        # Disable insecure connection warning.
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        url = f"{env_config['portal']['fqdn']}/user/login"
        self.username = os.getenv("test_username")
        password = os.getenv("test_password")

        try:
            # Retrieve the login CSRF token.
            response = self.client.get(url, verify=False)
            content = response.text
            found_csrf_tokens = CSRF_TOKEN_PATTERN.findall(content)
            if not found_csrf_tokens:
                print(f"Portal: could not find login CSRF token for user <{self.username}>. Response was: {content}")
                return None
            csrf = found_csrf_tokens[0]

            # Login as user.
            print(f"Portal: login for user <{self.username}>")

            login_data = {'csrf_token': csrf, 'username': self.username, 'password': password, 'next': '/'}
            response = self.client.post(url, data=login_data, headers={'Referer': url}, verify=False)

            # Check for successful login by looking for session cookie.
            session_cookie = self.client.cookies.get('__Host-session')
            if not session_cookie:
                print(f"Portal: login failed for user <{self.username}>, no session cookie found")
                return None

            # Retrieve the authenticated CSRF token.
            print(f"Portal: retrieve login CSRF token for user <{self.username}>")
            content = response.text
            found_csrf_tokens = CSRF_TOKEN_PATTERN.findall(content)
            if not found_csrf_tokens:
                print(f"Portal: could not find CSRF token for user <{self.username}>, response was: {content}")
                return None
            csrf = found_csrf_tokens[0]

            self.portal_csrf = csrf
            self.portal_session_cookie = session_cookie
        except Exception as e:
            print(f"Portal: error during portal login for user <{self.username}>: {e}")
            return None

    def on_stop(self) -> None:
        env_config = self.environment.parsed_options.environment
        url = f"{env_config['portal']['fqdn']}/user/logout"
        self.client.get(url, verify=False)
        print(f"Portal: logout for user <{self.username}>")

    def api_request(self, request: str, data: dict[str, str]) -> tuple[int, dict[str, str]]:
        env_config = self.environment.parsed_options.environment

        # Make API request.
        url = f"{env_config['portal']['fqdn']}/api/{request}"
        files = {'csrf_token': (None, self.portal_csrf), 'data': (None, json.dumps(data))}
        headers = {'referer': env_config['portal']['fqdn']}
        print(f"API: processing request <{request}> for user <{self.username}> with data <{data}>")

        with self.client.post(
            url,
            headers=headers,
            files=files,
            cookies={'__Host-session': self.portal_session_cookie},
            verify=False,
            timeout=30,
            catch_response=True
        ) as response:

            # Remove debug info from response body.
            status = response.status_code
            body = response.text
            if status in (200, 201, 202, 204):
                response.success()
            else:
                response.failure(
                    f"Upload failed: HTTP {status}; body={body[:300]}"
            )

        return response.status_code, body

    def upload_data(self, file, folder,file_content):
        env_config = self.environment.parsed_options.environment
        # Disable insecure connection warning.
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Make POST request.
        url = f"{env_config['portal']['fqdn']}/research/upload"

        # filename = os.path.basename(file)


        files = {"csrf_token": (None, self.portal_csrf),
                "filepath": (None, folder),
                "flowChunkNumber": (None, "1"),
                "flowChunkSize": (None, "10485760"),
                "flowCurrentChunkSize": (None,"4"),
                "flowTotalSize": (None, "4"),
                "flowIdentifier": (None, "4-{}".format(file)),
                "flowFilename": (None, file),
                "flowRelativePath": (None, file),
                "flowTotalChunks": (None, "1"),
                "file": (file, file_content)}

        cookies={'__Host-session': self.portal_session_cookie}
        headers = {'referer': url}
        with self.client.post(
            url,
            headers=headers,
            files=files,
            cookies=cookies,
            verify=False,
            timeout=30,
            catch_response=True
        ) as response:
            body = response.text
            status = response.status_code
            if status in (200, 201, 202, 204):
                response.success()
            else:
                response.failure(
                    f"Upload failed: HTTP {status}; "
                    f"body={body[:300]}"
                )

        print("status:", response.status_code)
        print("content-type:", response.headers.get("Content-Type"))
        print("text:", repr(response.text))

        body = ""
        return (response.status_code, body)


    @task(1)
    def api_group_data(self) -> None:
        status, body = self.api_request("group_data", {})

    @task(1)
    def api_resource_category_stats(self) -> None:
        status, body = self.api_request("resource_category_stats", {})

    @task(1)
    def api_resource_monthly_category_stats(self) -> None:
        status, body = self.api_request("resource_monthly_category_stats", {})

    @tag("upload")
    @task(1)
    def api_research_file_upload(self) -> None:
        env_config = self.environment.parsed_options.environment
        temp_file_path = create_temp_binary_file(1)

        #target_folder = "research-default-0"
        target_folder = env_config['irods']['test_workdir']
        filename = os.path.basename(temp_file_path)
        with open(temp_file_path, "rb") as f:
            content = f.read()

        status, body = self.upload_data(filename, target_folder, content)

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
    while environment.runner.state not in {
        STATE_STOPPING,
        STATE_STOPPED,
        STATE_CLEANUP,
    }:
        gevent.sleep(5)

        stats = environment.runner.stats.total
        completed = stats.num_requests
        if completed > last_completed:
            last_completed = completed
            last_progress_time = time.monotonic()
        no_progress_for = time.monotonic() - last_progress_time

        if no_progress_for >= NO_PROGRESS_SECONDS:
            logging.error(
                "Stopping: no requests completed for %.1f seconds",
                no_progress_for,
            )
            environment.runner.quit()
            return


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
    if isinstance(environment.runner, (LocalRunner, MasterRunner)):
        gevent.spawn(breaking_point_monitor, environment)