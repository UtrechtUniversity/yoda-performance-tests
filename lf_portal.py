#!/usr/bin/env python3
__license__ = 'GPLv3, see LICENSE'

import json
import re
import tempfile
import os
from urllib import response

import urllib3
from locust import constant, HttpUser, task

# Precompiled regex patterns
CSRF_TOKEN_PATTERN = re.compile(r"tokenValue: '([a-zA-Z0-9._-]*)'")


class PortalBaseUser(HttpUser):
    # This class is meant to be subclassed, this is indicated by setting the class variable 'abstract' to True
    abstract = True
    wait_time = constant(1)
    host = "https://yd06.yodadtap.src.surf-hosted.nl:8443"

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
        self.username = "researcher"
        password = "test"

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

        response = self.client.post(
            url,
            headers=headers,
            files=files,
            cookies={'__Host-session': self.portal_session_cookie},
            verify=False,
            timeout=60
        )

        # Remove debug info from response body.
        body = response.json()

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
        response = self.client.post(
            url,
            headers=headers,
            files=files,
            cookies=cookies,
            verify=False,
            timeout=60
        )
        # body = response.json()

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

    @task(1)
    def api_research_file_upload(self) -> None:
        temp_file_path = create_temp_binary_file(1)
        remote_file_path = f"/tempZone/home/research-default-0/{os.path.basename(temp_file_path)}"
        target_folder = "research-default-0"

        filename = os.path.basename(temp_file_path)
        with open(temp_file_path, "rb") as f:
            content = f.read()

        status, body = self.upload_data(filename, target_folder, content)
