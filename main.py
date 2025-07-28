#!/usr/bin/env python3

__copyright__ = 'Copyright (c) 2025, Utrecht University'
__license__   = 'GPLv3, see LICENSE'

import argparse
import datetime
import json
import logging
import os
import re
import time
from concurrent.futures import as_completed, ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple

import matplotlib.pyplot as plt
import numpy as np
import requests
import urllib3
from irods.session import iRODSSession
from webdav3.client import Client

# Configuration for Yoda.
IRODS_HOST = 'portal.yoda.test'
IRODS_PORT = 1247
IRODS_ZONE = 'tempZone'
PORTAL_FQDN = f"https://{IRODS_HOST}"
WEBDAV_FQDN = "https://data.yoda.test"

IRODS_SESSION_OPTIONS = {
    "irods_client_server_policy": "CS_NEG_REQUIRE",
    "irods_client_server_negotiation": "request_server_negotiation",
    "irods_encryption_key_size": 32,
    "irods_encryption_salt_size": 8,
    "irods_encryption_num_hash_rounds": 16,
    "irods_encryption_algorithm": "AES-256-CBC",
    'authentication_scheme': "pam_password",
    'application_name': 'yoda-performance-tests'
}

# Configure logging
LOGGING_FORMAT = "%(asctime)s %(message)s"
logging.basicConfig(level=logging.INFO, format=LOGGING_FORMAT)
logger = logging.getLogger(__name__)

# Precompiled regex patterns
CSRF_TOKEN_PATTERN = re.compile(r"tokenValue: '([a-zA-Z0-9._-]*)'")


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-s", "--sessions", nargs='+', type=int, default=10,
        help="Number of sessions to open in total (default: %(default)s)"
    )
    parser.add_argument(
        "-c", "--concurrent-sessions", type=int, default=2,
        help="Specify the number of concurrent sessions to run (default: %(default)s)"
    )
    parser.add_argument(
        "-u", "--users", type=str, default="users.json",
        help="Path to the JSON file containing user credentials (default: %(default)s)"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", default=False,
        help="Verbose mode - display additional information for troubleshooting"
    )
    parser.add_argument(
        "-k", "--insecure", action="store_true", default=False,
        help="Disables SSL certificate verification"
    )
    parser.add_argument(
        "-g", "--graph", action="store_true", default=False,
        help="Generate graph of performance test results"
    )
    return parser.parse_args()


def irods_login(user: Dict[str, str], verbose: bool) -> Optional[iRODSSession]:
    """Start session with iRODS."""
    try:
        with iRODSSession(
            host=IRODS_HOST,
            port=IRODS_PORT,
            user=user['username'],
            password=user['password'],
            zone=IRODS_ZONE,
            configure=True,
            **IRODS_SESSION_OPTIONS
        ) as session:
            _ = session.server_version  # Implicitly creates connections

        if verbose:
            logger.info(f"iRDOS: user <{user['username']}> logged in successfully")
        return session
    except Exception as e:
        if verbose:
            logger.error(f"iRDOS: failed to log in user <{user['username']}>: {e}")
        return None


def irods_logout(session: iRODSSession, verbose: bool) -> None:
    """End session with iRODS."""
    try:
        session.cleanup()
        if verbose:
            logger.info("iRDOS: user logged out successfully")
    except Exception as e:
        if verbose:
            logger.error(f"iRDOS: failed to log out user: {e}")


def portal_login(user: Dict[str, str], verbose: bool, insecure: bool) -> Optional[Tuple[str, str, str]]:
    """Start session with Yoda portal."""
    username = user['username']
    password = user['password']

    if insecure:
        # Disable insecure connection warning.
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    url = f"{PORTAL_FQDN}/user/login"
    if verbose:
        logger.info(f"Portal: retrieve CSRF token for user <{username}>")

    with requests.Session() as client:
        # Retrieve the login CSRF token.
        try:
            content = client.get(url, verify=not insecure).content.decode()
            found_csrf_tokens = CSRF_TOKEN_PATTERN.findall(content)
            if not found_csrf_tokens:
                if verbose:
                    logger.error(f"Portal: could not find login CSRF token for user <{username}>. Response was: {content}")
                return None
            csrf = found_csrf_tokens[0]

            # Login as user.
            if verbose:
                logger.info(f"Portal: login for user <{username}>")

            login_data = {'csrf_token': csrf, 'username': username, 'password': password, 'next': '/'}
            response = client.post(url, data=login_data, headers={'Referer': url}, verify=not insecure)

            # Check for successful login by looking for session cookie.
            session_cookie = client.cookies.get('__Host-session')
            if not session_cookie:
                if verbose:
                    logger.error(f"Portal: login failed for user <{username}>, no session cookie found")
                return None

            # Retrieve the authenticated CSRF token.
            content = response.content.decode()
            found_csrf_tokens = CSRF_TOKEN_PATTERN.findall(content)
            if not found_csrf_tokens:
                if verbose:
                    logger.error(f"Portal: could not find CSRF token for user <{username}>, response was: {content}")
                return None
            csrf = found_csrf_tokens[0]

            if verbose:
                logger.info(f"Portal: retrieve login CSRF token for user <{username}>")
            return username, csrf, session_cookie

        except Exception as e:
            if verbose:
                logger.error(f"Portal: error during portal login for user <{username}>: {e}")
            return None


def api_request(user: Tuple[str, str, str],
                request: str, data: Dict[str, str],
                verbose: bool, insecure: bool) -> Tuple[int, Dict[str, str]]:
    # Retrieve user cookies.
    username, csrf, session = user

    if insecure:
        # Disable insecure connection warning.
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Make API request.
    url = PORTAL_FQDN + "/api/" + request
    files = {'csrf_token': (None, csrf), 'data': (None, json.dumps(data))}
    cookies = {'__Host-session': session}
    headers = {'referer': PORTAL_FQDN}
    if verbose:
        logger.info(f"API: processing request <{request}> for user <{username}> with data <{data}>")
    response = requests.post(url, headers=headers, files=files, cookies=cookies, verify=not insecure, timeout=60)

    # Remove debug info from response body.
    body = response.json()

    return response.status_code, body


def get_data_access_password(user: Tuple[str, str, str], verbose: bool, insecure: bool) -> str:
    # Get the current timestamp
    timestamp = datetime.datetime.now()
    nice_timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
    label = f"Yoda Performance Test {nice_timestamp}"
    status, body = api_request(
        user, "token_generate", {"label": label}, verbose, insecure
    )
    return body['data']


def webdav_login(user: Dict[str, str], verbose: bool, insecure: bool) -> Optional[Dict[str, str]]:
    """Start session with WebDAV."""
    try:
        options = {
            'webdav_hostname': WEBDAV_FQDN,
            'webdav_login': user['username'],
            'webdav_password': user['data_access_password'],
        }

        client = Client(options)
        client.verify = not insecure
        client.check("/")

        if verbose:
            logger.info(f"WebDAV: user <{user['username']}> logged in successfully")
        return user
    except Exception as e:
        if verbose:
            logger.error(f"WebDAV: failed to log in user <{user['username']}>: {e}")
        return None


def load_users_from_json(file_path: str) -> List[Dict[str, str]]:
    """Load users from a JSON file."""
    if not os.path.exists(file_path):
        raise FileNotFoundError

    with open(file_path, 'r') as file:
        users = json.load(file)

    return users


def plot_results_graph(results: Dict, concurrent_sessions: int) -> None:
    # Prepare results for plotting.
    labels = list(results.keys())

    irods_values = [results[key]['irods'] for key in labels]
    portal_values = [results[key]['portal'] for key in labels]
    webdav_values = [results[key]['webdav'] for key in labels]

    x = np.arange(len(labels))
    width = 0.25

    # Create the bar graph.
    fig, ax = plt.subplots()
    ax.bar(x - width, irods_values, width, label='iRODS')
    ax.bar(x, portal_values, width, label='Portal')
    ax.bar(x + width, webdav_values, width, label='WebDAV')

    # Add labels.
    ax.set_xlabel('Sessions')
    ax.set_ylabel('Time (s)')
    ax.set_title(f'Yoda login performance (concurrent sessions: {concurrent_sessions})')
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.legend()

    # Save the figure.
    plt.savefig('yoda_login_performance.png')


def main() -> None:
    """Main function to manage sessions with specified number of concurrent threads."""
    args = parse_args()
    verbose = args.verbose
    insecure = args.insecure
    results = {}

    # Load users from JSON file.
    try:
        users = load_users_from_json(args.users)
    except FileNotFoundError:
        logger.error(f"ERROR: Users file not found: {args.users}")
        return None

    def manage_session(action: str, user: Dict[str, str], session_list: List, session_type: str) -> None:
        """Manage session login or logout."""
        try:
            if action == 'login':
                if session_type == 'irods':
                    session = irods_login(user, verbose)
                elif session_type == 'portal':
                    session = portal_login(user, verbose, insecure)
                elif session_type == 'webdav':
                    session = webdav_login(user, verbose, insecure)
                if session:
                    session_list.append(session)
            elif action == 'logout':
                if session_type == 'irods':
                    irods_logout(user, verbose)
        except Exception as e:
            if verbose:
                logger.error(f"Error during {action} for {session_type}: {e}")

    # Start sessions
    for sessions in args.sessions:
        irods_sessions = []     # List to store iRODS sessions.
        portal_sessions = []    # List to store portal sessions.
        webdav_sessions = []    # List to store WebDAV sessions.
        results[sessions] = {}  # Dict to store test results for this session.

        with ThreadPoolExecutor(max_workers=args.concurrent_sessions) as executor:
            # iRODS login.
            start_time = time.time()
            futures = {executor.submit(manage_session, 'login', users[i % len(users)], irods_sessions, 'irods'):
                       i for i in range(sessions)}
            for future in as_completed(futures):
                future.result()

            total_time = time.time() - start_time
            logger.info(f"iRODS: {len(irods_sessions)}/{sessions} sessions "
                        f"(concurrency: {args.concurrent_sessions}) in {total_time:.2f} seconds")
            results[sessions]["irods"] = total_time

            # iRODS logout.
            futures = {executor.submit(manage_session, 'logout', session, irods_sessions, 'irods'):
                       session for session in irods_sessions}
            for future in as_completed(futures):
                future.result()

            # Portal login.
            start_time = time.time()
            futures = {executor.submit(manage_session, 'login', users[i % len(users)], portal_sessions, 'portal'):
                       i for i in range(sessions)}
            for future in as_completed(futures):
                future.result()

            total_time = time.time() - start_time
            logger.info(f"Portal: {len(portal_sessions)}/{sessions} sessions "
                        f"(concurrency: {args.concurrent_sessions}) in {total_time:.2f} seconds")
            results[sessions]["portal"] = total_time

            # Retrieve Data Access Passwords for WebDAV login.
            for user in users:
                portal_session = next((session for session in portal_sessions if session[0] == user['username']), None)
                if portal_session:
                    user['data_access_password'] = get_data_access_password(portal_session, verbose, insecure)

            # WebDAV login.
            start_time = time.time()
            futures = {executor.submit(manage_session, 'login', users[i % len(users)], webdav_sessions, 'webdav'):
                       i for i in range(sessions)}
            for future in as_completed(futures):
                future.result()

            total_time = time.time() - start_time
            logger.info(f"WebDAV: {len(webdav_sessions)}/{sessions} sessions "
                        f"(concurrency: {args.concurrent_sessions}) in {total_time:.2f} seconds")
            results[sessions]["webdav"] = total_time

    if args.graph:
        plot_results_graph(results, args.concurrent_sessions)


if __name__ == "__main__":
    main()
