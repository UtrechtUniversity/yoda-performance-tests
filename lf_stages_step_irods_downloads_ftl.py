#!/usr/bin/env python3
__license__ = 'GPLv3, see LICENSE'
import time
import sys

from locust import LoadTestShape

from lf_irods import IrodsDownloadUser, IrodsUploadUser


def create_stage(name: str, user_classes: list, attime: int = 30, user_count:int = 20, spawn_rate:int = 5, user_params: dict | None = None):
    return {
        "name": name,
        "attime": attime,
        "user_count": user_count,
        "spawn_rate": spawn_rate,
        "user_classes": user_classes,
        "user_params": user_params
    }


class IrodsStepStages(LoadTestShape):
    """
    iRODS test stages: you can specify different users, with different spawn rates and runtimes.

    Keyword Arguments:
    -----------------
        stages -- A list of dicts, each representing a stage with the following keys:
            name -- The name of the stage
            duration -- When this many seconds pass the test is advanced to the next stage
            user_count -- Total user count
            spawn_rate -- Number of users to start/stop per second
            user_classes -- A list of classes that need to be run in the stage
            user_params -- A dictionary for passing arguments (appearing as attr in the class) {class_name: {arg: value}}
            stop -- A boolean that can stop that test at a specific stage

    """

    time_step = 30
    user_step = 20
    num_steps = 6

    stages = [
        create_stage(
            name = f"irods download: {us} users for {ts} seconds",
            user_classes = [IrodsDownloadUser],
            attime = ts,
            user_count = us,
            spawn_rate = 5,
            user_params = {"IrodsDownloadUser": {"file_size_mb": 5, "testuser": "researcher"}}
        )
        for ts, us in zip(
            range(time_step, (num_steps + 1) * time_step, time_step),
            range(user_step, (num_steps + 1) * user_step, user_step),
        )
    ]
    print(stages)


    def __init__(self, *args: int, **kwargs: str) -> None:
        self.stage_number = 0
        super().__init__(*args, **kwargs)


    def tick(self) -> tuple | None:
        try:
            stage = self.stages[self.stage_number]
        except IndexError:
            print("We are at the end of the stages, stopping...")
            # Exit if running in headless mode, otherwise allow UI to stay open
            return None
            #if getattr(self.environment.parsed_options, "headless", False):
            #    sys.exit(0)
            #else:
            #    return None

        print(f"[T: {self.get_run_time()}] Running stage: {stage['name']} [{self.stage_number}] |"
              f"#users: {self.get_current_user_count()}")
        print(f"Current running users: {self.runner.user_classes_count}")

        # Apply per‑class parameters if provided
        for user_cls in stage.get("user_classes", []):
            params = stage.get("user_params", {}).get(user_cls.__name__, {})
            for key, value in params.items():
                setattr(user_cls, key, value)

        if self.get_run_time() > stage["attime"]:
            # Move to the next stage. This will be active in the next tick
            self.stage_number += 1

        # Launch the next tick
        tick_data = (stage["user_count"], stage["spawn_rate"], stage["user_classes"])
        return tick_data
