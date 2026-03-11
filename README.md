# Yoda performance tests

This project provides tools for performing performance tests for [Yoda](https://github.com/UtrechtUniversity/yoda).

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/UtrechtUniversity/yoda-performance-tests.git
   cd yoda-performance-tests
   ```

2. Install the required dependencies:

   ```bash
   pip install .
   ```

   Or if you prefer `uv`:
   ```bash
   uv lock
   uv sync
   ```

   If you want to develop on these tools, also install the dev extras:
   ```bash
   pip install .[dev]
   ```

   Or if you prefer `uv`:
   ```bash
   uv sync --extra dev
   ```

## Usage Locust

You can run tests using locust (omit `uv run` if you installed with pip):

```bash
uv run locust -f lf_init.py,lf_irods.py --environment environments/development.json
```
This will run all Tests (tasks contained in classes derived from locust.User) as tests indefinitely. In this
the iRODS tests.

There is also the possibility to run a couple of tests after each other in more **staged** fashion:
```bash
uv run locust -f lf_init.py,lf_irods.py,lf_stages.py --environment environments/development.json
```

## Roadmap

- [x] Setting locust framework
- [x] Exploration of staged runs, first version
- [x] IRODSUser tests blueprint
- [ ] Portal tests blueprint
- [ ] WebDav tests blueprint
- [ ] Parameterization of the User classes in a staged run
- [ ] Multi worker runs
- [ ] Headless, autostart/autostop runs
- [ ] Machine readable reporting


## Usage of the performance test scripts

There is also still the possibility to the tests as was initially designed:

```bash
yoda-performance-tests -s <sessions>
```

### Arguments

The following command-line arguments can be specified:

| Argument                | Short Form | Type   | Default    | Description                                                             |
|-------------------------|------------|--------|------------|-------------------------------------------------------------------------|
| `--sessions`            | `-s`       | int[]  | 10         | Number of sessions to open in total (default: 10)                       |
| `--concurrent-sessions` | `-c`       | int    | 2          | Specify the number of concurrent sessions to run (default: 2)           |
| `--users`               | `-u`       | str    | users.json | Path to the JSON file containing user credentials (default: users.json) |
| `--verbose`             | `-v`       | bool   | False      | Verbose mode - display additional information for troubleshooting       |
| `--insecure`            | `-k`       | bool   | False      | Disables SSL certificate verification                                   |
| `--graph`               | `-g`       | bool   | False      | Generate graph of performance test results                              |


## Collaboration
This project is a collaboration between Utrecht University and SURF.

## License
This project is licensed under the GPL-v3 license.
The full license can be found in [LICENSE](LICENSE).
