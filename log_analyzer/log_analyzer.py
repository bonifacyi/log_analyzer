#!/usr/bin/env python
# -*- coding: utf-8 -*-

# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';

import re
import os
import gzip
import json
import sys
import logging
import argparse
from datetime import datetime
from collections import defaultdict, namedtuple
from string import Template
from statistics import median

parser = argparse.ArgumentParser(description='Log analyzer')
parser.add_argument('--config', type=str, default='../config.json', help='Path to users config file')
args = parser.parse_args()

config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "../data/reports",
    "LOG_DIR": "../data/log",
    "TEMPLATE": "../static/report.html",
    "LOG_FILENAME_PATTERN": "nginx-access-ui\\.log-(\\d{8})(?:\\.(gz))?$",
    "LOG_MSG_PATTERN": "\"[A-Z]+\\s([^\\s]+).+?([\\.\\d]+)$",
    "LOGGING_FILENAME": None,
    "BAD_MSG_PERC": 20,
}


def load_config_file(conf, config_file_path):
    """
    Load json config file and update script config

    Params:
        conf: dict
        config_file: str
    :return: conf: dict
    """
    try:
        with open(config_file_path) as f:
            cfg = f.read().strip()
            custom_config = json.loads(cfg) if cfg else dict()
    except FileNotFoundError:
        print(f'Config file <{config_file_path}> not found. Close...')
        sys.exit(1)
    except json.decoder.JSONDecodeError:
        print(f'Config file <{config_file_path}> is not valid json. Close...')
        sys.exit(1)

    # change configuration parameters that are defined in the config file
    for key, value in custom_config.items():
        conf[key] = value

    return conf


def get_last_log_file(log_dir_name, list_dir, log_filename_pattern):
    """
    Get name of folder with nginx logs, list of files in this folder
    and pattern for finding nginx log files.
    Return namedtuple object with absolute path to log file,
    log date (year, month, date) and compression method.

    Params:
        log_dir_name: str
        list_dir: list
        log_filename_pattern: str
    :return: namedtuple
    """
    log_file_path = None
    log_date = 0
    log_compress = None

    for filename in list_dir:
        m = re.match(log_filename_pattern, filename)
        if m is not None:
            date, compress = m.groups()
            date = int(date)
            if (date > log_date) or (date == log_date and compress is None):
                log_file_path, log_date, log_compress = filename, date, compress

    if log_file_path:
        log_file_path = os.path.join(log_dir_name, log_file_path)
        log_date = datetime.strptime(str(log_date), '%Y%m%d')

    log_file_meta = ['log_file_path', 'year', 'month', 'day', 'compress']
    Meta = namedtuple('Meta', log_file_meta)
    return Meta(
        log_file_path,
        log_date.strftime('%Y'),
        log_date.strftime('%m'),
        log_date.strftime('%d'),
        log_compress
    )


def find_metrics_in_log_msg(compiled_pattern, line):
    metrics = None
    res = compiled_pattern.search(line)
    if res is not None:
        metrics = res.groups()

    return metrics


def log_data_generator(open_file, compiled_pattern, log_compress=None):
    """
    Generator for sequential line-by-line log file reading
    Return url and request time finding in line with <find_metrics_in_log_msg>

    Params:
        open_file: file object
        compiled_pattern:
        og_compress: str
    :return: metrics: tuple
    """
    for line in open_file:
        line = line.decode('utf-8') if log_compress else line

        yield find_metrics_in_log_msg(compiled_pattern, line)


def aggregate_log_data(data_generator):
    """
    Parse log file with log_data_generator (it returned tuple with metrics),
    gather metrics to default dict 'aggregated_data',
    calculate total requests time, total number of requests, total number of bad messages

    :param data_generator: generator object
        tuple: request_url, request_time
    :return: aggregated_data: dict
        data in format: {url<str>: [time<float>, ...], ...}
        for example: {'url1': [1.2, 3.4, ...], 'url2': [5.6, 7.8, ...], ...}
    :return: total_request_time: float
    :return: total_count: int
        total number of parsed requests
    :return: bad_log_msgs: int
    """
    bad_log_msgs = 0
    total_count = 0
    total_request_time = float()
    aggregated_data = defaultdict(list)
    for metrics in data_generator:
        if metrics is None:
            bad_log_msgs += 1
            continue

        request_url, request_time = metrics
        request_time = float(request_time)

        aggregated_data[request_url].append(request_time)

        total_request_time += request_time
        total_count += 1

    return aggregated_data, total_request_time, total_count, bad_log_msgs


def calculate_json_table(aggregated_data, total_request_time, total_count, report_size):
    """
    Calculate report and convert it to json table

    Params:
        aggregated_data: dict
            data in format: {url<str>: [time<float>, ...], ...}
            for example: {'url1': [1.2, 3.4, ...], 'url2': [5.6, 7.8, ...], ...}
        total_request_time: float
        total_count: int
            total number of parsed requests
        report_size: int
            config["REPORT_SIZE"] - count of urls in report with most total request time
    :return: json_table: str(json)
        report serialized to json table
    """
    table = list()
    for url, time_list in aggregated_data.items():
        url_data = dict()

        url_data['url'] = url
        url_data['count'] = len(time_list)
        url_data['time_max'] = round(max(time_list), 3)
        url_data['time_sum'] = round(sum(time_list), 3)
        url_data['time_avg'] = round(url_data['time_sum'] / url_data['count'], 3)
        url_data['time_perc'] = round(100 * url_data['time_sum'] / total_request_time, 3)
        url_data['count_perc'] = round(100 * url_data['count'] / total_count, 3)
        url_data['time_med'] = round(median(time_list), 3)

        table.append(url_data)

    sorted_table = sorted(table, key=lambda d: d['time_sum'], reverse=True)[:report_size]
    json_table = json.dumps(sorted_table)
    return json_table


def rendering_report(table, template_path, report_path):
    """
    Params:
        table: str(json)
        template_path: str(full path)
        report_path: str(full path)
    :return: None
    """
    with open(template_path, 'r') as tmpl:
        template_html = Template(tmpl.read())

    report_html = template_html.safe_substitute(table_json=table)

    with open(report_path, 'w') as report:
        report.write(report_html)


def main(conf):

    logging.info('-'*50)
    logging.info(f'START GENERATING REPORT')

    log_dir_name = os.path.abspath(conf['LOG_DIR'])
    if os.path.isdir(log_dir_name):
        logging.info(f'Log folder <{log_dir_name}>')
    else:
        logging.error(f'Log folder <{log_dir_name}> not found!')
        sys.exit(1)

    template_path = os.path.abspath(conf['TEMPLATE'])
    if os.path.isfile(template_path):
        logging.info(f'Template html <{template_path}>')
    else:
        logging.error(f'Template html <{template_path}> not found!')
        sys.exit(1)

    report_dir = os.path.abspath(conf['REPORT_DIR'])
    if os.path.isdir(report_dir):
        logging.info(f'Report folder <{report_dir}>')
    else:
        logging.info(f'Report folder <{report_dir}> not found. It will be created')
        try:
            os.makedirs(report_dir)
        except:
            logging.exception(f'Make folder <{report_dir}>')
            sys.exit(1)

    try:
        list_dir = os.listdir(log_dir_name)
        log_meta = get_last_log_file(log_dir_name, list_dir, conf['LOG_FILENAME_PATTERN'])
    except:
        logging.exception('Get last log file error. Close')
        sys.exit(1)
    logging.info(f'Last nginx log file: {log_meta.log_file_path}')
    if log_meta.log_file_path is None:
        logging.info('Nginx log files not found. Close')
        sys.exit(0)

    report_file_path = os.path.join(
        report_dir,
        f'report-{log_meta.year}.{log_meta.month}.{log_meta.day}.html'
    )
    if os.path.isfile(report_file_path):
        logging.info(f'Report file <{report_file_path}> already exist. Close')
        sys.exit(0)

    logging.info('Read nginx log file...')
    open_file = gzip.open(log_meta.log_file_path, 'rb') if log_meta.compress else open(log_meta.log_file_path, 'r')
    compiled_pattern = re.compile(conf["LOG_MSG_PATTERN"])
    log_data = log_data_generator(open_file, compiled_pattern, log_meta.compress)
    try:
        aggregated_data, total_request_time, total_count, bad_log_msg = aggregate_log_data(log_data)
    except gzip.BadGzipFile:
        logging.error(f'Bad gzip file <{log_meta.log_file_path}>. Close')
        sys.exit(1)
    except:
        logging.exception('Aggregate log error. Close')
        sys.exit(1)
    finally:
        open_file.close()

    logging.info(f'Parsed {total_count} notices, {bad_log_msg} unable to parse, found {len(aggregated_data)} urls')

    if (100 * bad_log_msg / total_count) >= conf["BAD_MSG_PERC"]:
        logging.error(f'Count of bad log messages more then limit {conf["BAD_MSG_PERC"]}%')
        sys.exit(1)

    logging.info('Calculate report and convert it to json')
    try:
        json_table = calculate_json_table(
            aggregated_data,
            total_request_time,
            total_count,
            conf['REPORT_SIZE']
        )
    except:
        logging.exception(f'Generate json report error. Close')
        sys.exit(1)
    logging.info('Calculate and convert json report success')

    try:
        rendering_report(json_table, template_path, report_file_path)
    except:
        logging.exception('Rendering report error. Close')
        sys.exit(1)
    logging.info(f'Report is ready <{report_file_path}>')


if __name__ == "__main__":
    # update config
    config_file = os.path.abspath(args.config)
    config = load_config_file(config, config_file)

    # init logging config
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] (%(levelname).1s) %(message)s',
        datefmt='%Y.%m.%d %H:%M:%S',
        filename=config["LOGGING_FILENAME"],
    )

    main(config)
