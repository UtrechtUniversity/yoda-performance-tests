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
from locust.user.markov_taskset import (
    MarkovTaskSet,
    transition,
    transitions,
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

def create_temp_binary_file(size_mb: int) -> str:
    # Calculate the size in bytes
    size_bytes = size_mb * 1024 * 1024
    # Create a temporary file
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        # Write zeros to the file to fill it to the desired size
        tmp.write(b'\0' * size_bytes)
        tmp_path = tmp.name
    return tmp_path

class YodaPortalUser(HttpUser):
    # This class is meant to be subclassed, this is indicated by setting the class variable 'abstract' to True
    abstract = True
    wait_time = constant(1)
    host = "https://surf-yoda.irods.surfsara.nl"

    username: str = ""
    portal_csrf: str = ""
    portal_session_cookie: str = ""
    download_dir: str = ""
    download_index: int = 0
    download_files: list[str] = []
    def on_start(self) -> None:
        env_config = self.environment.parsed_options.environment

        # Disable insecure connection warning.
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.download_dir = env_config['portal']['download_dir']
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
            print(f"Portal: login for user <{self.username}> of type <{self.__class__.__name__}>")

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
            # get list of files in download folder
            status, body  = self.api_request("browse_folder", {"coll":f"/{env_config['irods']['zone']}/home/{self.download_dir}","offset":0,"limit":200,"sort_order":"asc","sort_on":"name","space":"Space.RESEARCH"})
            folder_info = json.loads(body)
            if status != 200:
                print(f"Portal: could not list files in download folder for user <{self.username}>, response was: {folder_info}")

            elif status == 200:
                # print(f"Portal: list of files in download folder for user <{self.username}>: {folder_info}")
                self.download_files = [
                f"/{self.download_dir}/{item['name']}"
                for item in folder_info["data"]["items"]
                if item["type"] == "data"
                ]
            else:
                print(f"Portal: unexpected response code {status} for user <{self.username}>, response was: {body}")
                return None




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
            timeout=20,
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
            timeout=20,
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

    @tag("High-Cost")
    def api_group_data(self) -> None:
        status, body = self.api_request("group_data", {})

    @tag("High-Cost")
    def api_resource_category_stats(self) -> None:
        status, body = self.api_request("resource_category_stats", {})

    @tag("High-Cost")
    def api_resource_monthly_category_stats(self) -> None:
        status, body = self.api_request("resource_monthly_category_stats", {})

    @tag("upload")
    def api_research_file_upload(self) -> None:
        env_config = self.environment.parsed_options.environment
        temp_file_path = create_temp_binary_file(1)

        #target_folder = "research-default-0"
        target_folder = env_config['irods']['test_workdir']
        filename = os.path.basename(temp_file_path)
        with open(temp_file_path, "rb") as f:
            content = f.read()

        status, body = self.upload_data(filename, target_folder, content)

    @tag("browse")
    def browse(self, folder: str = None) -> None:
        env_config = self.environment.parsed_options.environment
        if folder is None:
            folder = f"/{env_config['irods']['zone']}/home/{self.download_dir}"
            print(f"folder is:{folder}")
        status, body  = self.api_request("browse_folder", {"coll": folder,"offset":0,"limit":200,"sort_order":"asc","sort_on":"name","space":"Space.RESEARCH"})
        if status != 200:
            print(f"Portal: could not list files in download folder for user <{self.username}>, response was: {status}")
        elif status == 200:
            # print(f"---------------------------------------------------------------------------------{body}")
            folder_info = json.loads(body)
            # print(f"Portal: list of files in download folder for user <{self.username}>: {folder_info}")
            self.download_files = [
                f"/{self.download_dir}/{item['name']}"
                for item in folder_info["data"]["items"]
                if item["type"] == "data"
            ]
        else:
            print(f"Portal: unexpected response code {status} for user <{self.username}>, response was: {body}")
            return None

    @tag("download")
    def download(self):
        if self.download_index >= len(self.download_files): self.download_index = 0
        filepath = self.download_files[self.download_index]
        self.download_index = self.download_index + 1
        start = time.perf_counter()
        with self.client.get(
            "/browse/download",
            params={"filepath": filepath},
            name="download",
            stream=True,
            catch_response=True,
        ) as response:
            first_byte_time = None
            total_bytes = 0
            for chunk in response.iter_content(chunk_size=64 * 1024):
                if first_byte_time is None:
                    first_byte_time = time.perf_counter()

                total_bytes += len(chunk)
            status = response.status_code
            if first_byte_time is not None:
                ttfb_ms = (first_byte_time - start) * 1000
                self.environment.events.request.fire(
                    request_type="TTFB",
                    name="download",
                    response_time=ttfb_ms,
                    response_length=0,
                    exception=None,
                    context={},
                )
                print(f"TTFB: {ttfb_ms:.2f} ms, Total bytes: {total_bytes}")
            if status in (200, 201, 202, 204):
                response.success()
                print(f"Download successful: HTTP {status}; for {filepath}")
            else:
                response.failure(
                    f"Download failed: {status}"
                )
                print(f"Download failed: HTTP {status}; for {filepath}")


# ============================================================
# RESEARCHER
# ============================================================
class ResearcherJourney(MarkovTaskSet):

    @transitions({
        "browse": 6,
        "download": 3,
        "upload": 3,
    })
    def browse(self):
        self.user.browse()

    @transitions({
        "browse": 6,
        "download": 3,
        "upload":3,
    })
    def download(self):
        self.user.download()


    @transitions({
        "browse": 6,
        "download": 3,
        "upload": 3,
    })
    def upload(self):
        self.user.api_research_file_upload()


class Researcher(YodaPortalUser):

    weight = 20
    tasks = [ResearcherJourney]
    wait_time = between(2, 15)


# ============================================================
# MANAGER
# ============================================================

class ManagerJourney(MarkovTaskSet):

    @transitions({
        "browse": 5,
        "group_data": 3,
        "resource_stats": 2,
        "monthly_stats": 1
    })
    def browse(self):
        self.user.browse()

    @transitions({
        "browse": 5,
        "group_data": 3,
        "resource_stats": 2,
        "monthly_stats": 1
    })
    def group_data(self):
        self.user.api_group_data()

    @transitions({
        "browse": 5,
        "group_data": 3,
        "resource_stats": 2,
        "monthly_stats": 1
    })
    def resource_stats(self):
        self.user.api_resource_category_stats()

    @transitions({
        "browse": 5,
        "group_data": 3,
        "resource_stats": 2,
        "monthly_stats": 1
    })
    def monthly_stats(self):
        self.user.api_resource_monthly_category_stats()


class Manager(YodaPortalUser):

    weight = 1
    tasks = [ManagerJourney]
    wait_time = between(3, 20)
