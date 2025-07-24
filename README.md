# Yoda performance tests

This project provides a Python script to perform performance tests for [Yoda](https://github.com/UtrechtUniversity/yoda).

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

## Usage

Run the performance test script from the command line, specifying the number of sessions to open:

```bash
yoda-performance-tests -s <sessions>
```

## Arguments

The following command-line arguments can be specified:

| Argument                | Short Form | Type   | Default | Description                                                       |
|-------------------------|------------|--------|---------|-------------------------------------------------------------------|
| `--sessions`            | `-s`       | int[]  | 10      | Number of sessions to open in total (default: 10)                 |
| `--concurrent-sessions` | `-c`       | int    | 2       | Specify the number of concurrent sessions to run (default: 2)     |
| `--verbose`             | `-v`       | bool   | False   | Verbose mode - display additional information for troubleshooting |
| `--insecure`            | `-k`       | bool   | False   | Disables SSL certificate verification                             |
| `--graph`               | `-g`       | bool   | False   | Generate graph of performance test results                        |

## License
This project is licensed under the GPL-v3 license.
The full license can be found in [LICENSE](LICENSE).
