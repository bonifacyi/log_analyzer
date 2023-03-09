# log_analyzer
 Otus Python Professional, task 03, Log Analyzer
> Analysis of the nginx log file to obtain query statistics and generate html report
## Usage
    $ git clone https://github.com/bonifacyi/log_analyzer.git
    $ cd log_analyzer
    $ python log_analyzer/log_analyzer.py --config='/path/to/config.json'
### Config file
Default config file is located at folder.
The path to the config file can be absolute or relative.
File format is json. Example:
```json
{
  "LOGGING_FILENAME": "/path/to/logging.log(stdout if absent)",
  "REPORT_SIZE": 1000,
  "REPORT_DIR": "/path/to/reports/folder",
  "LOG_DIR": "/path/to/nginx/logs/folder",
  "TEMPLATE": "/path/to/template/report.html",
  "LOG_FILENAME_PATTERN": "regex pattern of log file name",
  "LOG_MSG_PATTERN": "regex pattern to find metrics in log messages",
  "BAD_MSG_PERC": 20
}
```
### Run tests
    $ python tests/log_analyzer_tests.py