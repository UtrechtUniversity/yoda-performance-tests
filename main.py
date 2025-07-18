#!/usr/bin/env python3

__copyright__ = 'Copyright (c) 2025, Utrecht University'
__license__   = 'GPLv3, see LICENSE'

import argparse
import threading
import time
from typing import Dict, List, Optional

from irods.session import iRODSSession

# Configuration for Yoda.
IRODS_HOST = 'portal.yoda.test'
IRODS_PORT = 1247
IRODS_ZONE = 'tempZone'

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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-s",
        "--sessions",
        help="Number of sessions to open in total (default: 10)",
        type=int,
        default=10)
    parser.add_argument(
        "-c",
        "--concurrent-sessions",
        help="Specify the number of concurrent sessions to run (default: 2)",
        type=int,
        default=2)
    parser.add_argument(
        "-v",
        "--verbose",
        help="Verbose mode - display additional information for troubleshooting",
        action="store_true",
        default=False)

    args = parser.parse_args()

    return args


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
            # This implicitly creates connections, and raises an exception on failure.
            _ = session.server_version

        if verbose:
            print(f"User {user['username']} logged in successfully")
        return session
    except Exception as e:
        if verbose:
            print(f"Failed to log in user {user['username']}: {e}")
        return None


def irods_logout(session: iRODSSession, verbose: bool) -> None:
    """End session with iRODS."""
    try:
        session.cleanup()
        if verbose:
            print("User logged out successfully")
    except Exception as e:
        if verbose:
            print(f"Failed to log out user: {e}")


def main() -> None:
    """Main function to managed sessions with specified number of concurrent threads."""
    args = parse_args()
    verbose = args.verbose

    threads = []
    sessions = []                     # List to store iRODS sessions.
    sessions_lock = threading.Lock()  # Lock for thread-safe access to sessions.

    semaphore = threading.Semaphore(args.concurrent_sessions)

    def thread_irods_login(user: Dict[str, str], verbos: bool) -> None:
        with semaphore:
            session = irods_login(user, verbose)
            with sessions_lock:
                sessions.append(session)

    def thread_irods_logout(sessions: List[iRODSSession], verbos: bool) -> None:
        with semaphore:
            irods_logout(session, verbose)

    # Login users.
    start_time = time.time()
    for i in range(args.sessions):
        user = users[i % len(users)]  # Cycle through users if more sessions than users.
        thread = threading.Thread(target=thread_irods_login, args=(user, verbose))
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete.
    for thread in threads:
        thread.join()

    total_time = time.time() - start_time
    print(f"Started {args.sessions} sessions (concurrency: {args.concurrent_sessions}) in {total_time:.2f} seconds.")

    # Cleanup sessions.
    start_time = time.time()
    for session in sessions:
        thread = threading.Thread(target=thread_irods_logout, args=(session, verbose))
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete.
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()
