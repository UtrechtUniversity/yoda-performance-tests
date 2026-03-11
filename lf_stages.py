#!/usr/bin/env python3
__license__ = 'GPLv3, see LICENSE'
import time

from locust import LoadTestShape

from lf_irods import IrodsDownloadUser, IrodsUploadUser


class IrodsStages(LoadTestShape):
    """
    iRODS test stages: you can specify different users, with different spawn rates and runtimes.

    Keyword Arguments:
    -----------------
        stages -- A list of dicts, each representing a stage with the following keys:
            name -- The name of the stage
            duration -- When this many seconds pass the test is advanced to the next stage
            users -- Total user count
            spawn_rate -- Number of users to start/stop per second
            stop -- A boolean that can stop that test at a specific stage

    """

    stages = [
        {
            "name": "easy upload",
            "duration": 20,
            "user_count": 5,
            "spawn_rate": 0.5,
            "user_classes": [IrodsUploadUser]
        },
        {
            "name": "easy download",
            "duration": 20,
            "user_count": 5,
            "spawn_rate": 0.5,
            "user_classes": [IrodsDownloadUser]
        },
    ]

    def __init__(self, *args: int, **kwargs: str) -> None:
        self.stage_number = 0
        self.stopping_stage = False
        super().__init__(*args, **kwargs)

    def tick(self) -> tuple | None:
        try:
            stage = self.stages[self.stage_number]
        except IndexError:
            print("We are at the end of the stages, stopping...")
            return None

        print(f"[T: {self.get_run_time()}] Running stage: {stage['name']} [{self.stage_number}] |"
              f"#users: {self.get_current_user_count()}")
        print(f"Current running users: {self.runner.user_classes_count}")

        # Check if we can continue with this stage and if there is no active stop signal
        if self.get_run_time() > stage['duration'] and not self.stopping_stage:
            # The stage is done, initiate stopping this stage
            print(f"{stage['name']} stage should stop!")
            self.stopping_stage = True
            # Return a tick with 0 users and very high rate to keep on signalling a stop to the runner
            return (0, 100)

        if self.get_run_time() < stage["duration"] and not self.stopping_stage:
            # We can continue with this stage
            tick_data = (stage["user_count"], stage["spawn_rate"], stage["user_classes"])
            return tick_data
        elif self.stopping_stage and self.get_current_user_count() > 0:
            # The stage is still cleaning up, wait for a tick longer
            print(f"status: {self.runner.state}")
            print("still stopping...")
            # Return a tick with 0 users and very high rate to keep on signalling a stop to the runner
            return (0, 100)

        if self.stopping_stage and self.get_current_user_count() == 0:
            print("The stage has stopped, resetting timer and move to the next stage...")
            self.stopping_stage = False
            # Cooling down
            time.sleep(5)
            self.reset_time()
            self.stage_number += 1
            # Return this tick_data anyway, to make sure that the runner is not stopped pre-maturely.
            # (Since a return None, stops the runner completely)
            return (0, 100)

        return None
