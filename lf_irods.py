#!/usr/bin/env python3
__license__ = 'GPLv3, see LICENSE'

import os
import tempfile

import irods.keywords as kw
from irods.session import iRODSSession
from locust import constant, events, task, User


def create_temp_binary_file(size_mb: int) -> str:
    # Calculate the size in bytes
    size_bytes = size_mb * 1024 * 1024
    # Create a temporary file
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        # Write zeros to the file to fill it to the desired size
        tmp.write(b'\0' * size_bytes)
        tmp_path = tmp.name
    return tmp_path


def get_credentials(ctx, environment, user_credentials):
    # Try to get the username from env
    # otherwise, try to get it from the attr set from the stage config, ultimately fall back to the user: reseacher (from the yoda test data)
    if os.getenv('test_username'):
        selected_user = os.getenv('test_username')
    else:
        selected_user = getattr(ctx, 'testuser', 'researcher')

    # Same for password
    # if everything fails fall back to password "test" (from the yoda test data)
    if os.getenv('test_password'):
        password = os.getenv('test_password')
    elif user_credentials:
        password = next((x["password"] for x in user_credentials if x["username"] == selected_user), None)
    else:
        password = "test"
    
    return selected_user, password


class IrodsBaseUser(User):
    # This class is meant to be subclassed, this is indicated by setting the class variable 'abstract' to True
    abstract = True
    wait_time = constant(1)
    host = "https://portal.yoda:8443"
    # default file size in MB for temporary files
    file_size_mb = 1


class IrodsUploadUser(IrodsBaseUser):
    def on_start(self) -> None:
        env_config = self.environment.parsed_options.environment
        if hasattr(self.environment.parsed_options, "user_credentials"):
            users = self.environment.parsed_options.user_credentials
        else:
            users = None
        username, password = get_credentials(self, env_config, users)
        self.irods = iRODSSession(
            host=env_config['irods']['host'],
            port=env_config['irods']['port'],
            user=username,
            password=password,
            zone=env_config['irods']['zone'],
            configure=True,
            **env_config['irods']['session-options']
        )
        # create a file to upload
        self.temp_file_path = create_temp_binary_file(getattr(self, "file_size_mb", 1))
        self.remote_file_path = f"/{env_config['irods']['zone']}/home/{env_config['irods']['test_workdir']}/{os.path.basename(self.temp_file_path)}"
        print(f"Temporary file for upload user created (size = {self.file_size_mb} mb): {self.temp_file_path}")

    def on_stop(self) -> None:
        try:
            self.irods.data_objects.unlink(self.remote_file_path, **{kw.FORCE_FLAG_KW: True})
            print(f"Uploaded file for upload user removed: {self.remote_file_path}")
            self.irods.cleanup()
            os.remove(self.temp_file_path)
        except Exception:
            pass

    @task(1)
    def upload_file(self) -> None:
        request_type = "python-irods"
        request_name = "put file"
        with events.request.measure(request_type, request_name):
            self.irods.data_objects.put(self.temp_file_path, self.remote_file_path, **{kw.FORCE_FLAG_KW: True})


class IrodsDownloadUser(IrodsBaseUser):
    def on_start(self) -> None:
        env_config = self.environment.parsed_options.environment
        if hasattr(self.environment.parsed_options, "user_credentials"):
            users = self.environment.parsed_options.user_credentials
        else:
            users = None
        username, password = get_credentials(self, env_config, users)
        self.irods = iRODSSession(
            host=env_config['irods']['host'],
            port=env_config['irods']['port'],
            user=username,
            password=password,
            zone=env_config['irods']['zone'],
            configure=True,
            **env_config['irods']['session-options']
        )
        # create a file to download
        self.temp_file_path = create_temp_binary_file(getattr(self, "file_size_mb", 1))
        self.remote_file_path = f"/{env_config['irods']['zone']}/home/{env_config['irods']['test_workdir']}/{os.path.basename(self.temp_file_path)}"
        print(f"Temporary file for download user created (size = {self.file_size_mb} mb): {self.remote_file_path}")

        self.irods.data_objects.put(self.temp_file_path, self.remote_file_path, **{kw.FORCE_FLAG_KW: True})
        print(f"Temporary file for download user uploaded to yoda: {self.remote_file_path}")

    def on_stop(self) -> None:
        try:
            # Remove the uploaded file again:
            self.irods.data_objects.unlink(self.remote_file_path, **{kw.FORCE_FLAG_KW: ""})
            self.irods.cleanup()
        except Exception:
            pass

    @task(1)
    def download_file(self) -> None:
        request_type = "python-irods"
        request_name = "get file"
        with events.request.measure(request_type, request_name):
            self.irods.data_objects.get(self.remote_file_path, 'local_copy.bin', **{kw.FORCE_FLAG_KW: ""})
