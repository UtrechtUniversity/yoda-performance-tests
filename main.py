#!/usr/bin/env python3

__copyright__ = 'Copyright (c) 2025, Utrecht University'
__license__   = 'GPLv3, see LICENSE'

import argparse
import logging
import re
import time
from concurrent.futures import as_completed, ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple

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

# List of users and their passwords.
users = [
    {'username': 'researcher', 'password': 'test'},
    {'username': 'viewer', 'password': 'test'},
]

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Precompiled regex patterns
CSRF_TOKEN_PATTERN = re.compile(r"tokenValue: '([a-zA-Z0-9._-]*)'")


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-s", "--sessions", type=int, default=10,
        help="Number of sessions to open in total (default: 10)"
    )
    parser.add_argument(
        "-c", "--concurrent-sessions", type=int, default=2,
        help="Specify the number of concurrent sessions to run (default: 2)"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", default=False,
        help="Verbose mode - display additional information for troubleshooting"
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
            logger.info(f"User {user['username']} logged in successfully")
        return session
    except Exception as e:
        logger.error(f"Failed to log in user {user['username']}: {e}")
        return None


def irods_logout(session: iRODSSession, verbose: bool) -> None:
    """End session with iRODS."""
    try:
        session.cleanup()
        if verbose:
            logger.info("User logged out successfully")
    except Exception as e:
        logger.error(f"Failed to log out user: {e}")


def portal_login(user: Dict[str, str], verbose: bool) -> Optional[Tuple[str, str]]:
    """Start session with Yoda portal."""
    username = user['username']
    password = user['password']

    # Disable insecure connection warning.
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    url = f"{PORTAL_FQDN}/user/login"
    if verbose:
        logger.info(f"Login for user {username} (retrieve CSRF token)")

    with requests.Session() as client:
        # Retrieve the login CSRF token.
        try:
            content = client.get(url, verify=False).content.decode()
            found_csrf_tokens = CSRF_TOKEN_PATTERN.findall(content)
            if not found_csrf_tokens:
                logger.error(f"Portal: could not find login CSRF token for user {username}. Response was: {content}")
                return None
            csrf = found_csrf_tokens[0]

            # Login as user.
            if verbose:
                logger.info(f"Portal: login for user {username} (main login)")

            login_data = {'csrf_token': csrf, 'username': username, 'password': password, 'next': '/'}
            response = client.post(url, data=login_data, headers={'Referer': url}, verify=False)

            # Check for successful login by looking for session cookie.
            session_cookie = client.cookies.get('__Host-session')
            if not session_cookie:
                logger.error(f"Portal: login failed for user {username}. No session cookie found.")
                return None

            # Retrieve the authenticated CSRF token.
            content = response.content.decode()
            found_csrf_tokens = CSRF_TOKEN_PATTERN.findall(content)
            if not found_csrf_tokens:
                logger.error(f"Portal: could not find CSRF token for user {username}. Response was: {content}")
                return None
            csrf = found_csrf_tokens[0]

            if verbose:
                logger.info(f"Portal: login for user {username} completed.")
            return csrf, session_cookie

        except Exception as e:
            logger.error(f"Portal: error during portal login for user {username}: {e}")
            return None


def webdav_login(user: Dict[str, str], verbose: bool) -> Optional[Dict[str, str]]:
    """Start session with WebDAV."""
    try:
        options = {
            'webdav_hostname': WEBDAV_FQDN,
            'webdav_login': user['username'],
            'webdav_password': user['password'],
        }

        client = Client(options)
        client.verify = False
        client.check("/")

        if verbose:
            logger.info(f"WebDAV: user {user['username']} logged in successfully")
        return user
    except Exception as e:
        logger.error(f"WebDAV: failed to log in user {user['username']}: {e}")
        return None


def main() -> None:
    """Main function to manage sessions with specified number of concurrent threads."""
    args = parse_args()
    verbose = args.verbose

    irods_sessions = []   # List to store iRODS sessions.
    portal_sessions = []  # List to store portal sessions.
    webdav_sessions = []  # List to store WebDAV sessions.

    def manage_session(action: str, user: Dict[str, str], session_list: List, session_type: str) -> None:
        """Manage session login or logout."""
        try:
            if action == 'login':
                if session_type == 'irods':
                    session = irods_login(user, verbose)
                elif session_type == 'portal':
                    session = portal_login(user, verbose)
                elif session_type == 'webdav':
                    session = webdav_login(user, verbose)
                if session:
                    session_list.append(session)
            elif action == 'logout':
                if session_type == 'irods':
                    irods_logout(user, verbose)
        except Exception as e:
            logger.error(f"Error during {action} for {session_type}: {e}")

    # Start sessions
    with ThreadPoolExecutor(max_workers=args.concurrent_sessions) as executor:
        # iRODS login.
        start_time = time.time()
        futures = {executor.submit(manage_session, 'login', users[i % len(users)], irods_sessions, 'irods'):
                   i for i in range(args.sessions)}
        for future in as_completed(futures):
            future.result()

        total_time = time.time() - start_time
        logger.info(f"iRODS: {args.sessions} sessions (concurrency: {args.concurrent_sessions}) in {total_time:.2f} seconds")

        # iRODS logout.
        futures = {executor.submit(manage_session, 'logout', session, irods_sessions, 'irods'):
                   session for session in irods_sessions}
        for future in as_completed(futures):
            future.result()

        # Portal login.
        start_time = time.time()
        futures = {executor.submit(manage_session, 'login', users[i % len(users)], portal_sessions, 'portal'):
                   i for i in range(args.sessions)}
        for future in as_completed(futures):
            future.result()

        total_time = time.time() - start_time
        logger.info(f"Portal: {args.sessions} sessions (concurrency: {args.concurrent_sessions}) in {total_time:.2f} seconds")

        # Webdav login.
        start_time = time.time()
        futures = {executor.submit(manage_session, 'login', users[i % len(users)], webdav_sessions, 'webdav'):
                   i for i in range(args.sessions)}
        for future in as_completed(futures):
            future.result()

        total_time = time.time() - start_time
        logger.info(f"WebDAV: {args.sessions} sessions (concurrency: {args.concurrent_sessions}) in {total_time:.2f} seconds")


if __name__ == "__main__":
    main()
