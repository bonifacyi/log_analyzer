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
from datetime import datetime
from collections import defaultdict

config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "../data/reports",
    "LOG_DIR": "../data/log",
    "LOG_PATTERN": "nginx-access-ui\\.log-(\\d*)(\\.gz)?"
}


def get_last_log_file(log_dir, log_pattern):
    """
    В каталоге с логами ищет самый свежий файл логов nginx,
    возврщает полный путь к этому файлу и его дату создания
    :param log_dir: str
    :param log_pattern: str
    :return: log_file_path: str
    :return: log_date: datetime object
    :return: log_compress: str or None
    """
    log_dir_abs = os.path.abspath(log_dir)
    log_file_path = None
    log_date = 0
    log_compress = None

    for filename in os.listdir(log_dir_abs):
        m = re.match(log_pattern, filename)
        if m is not None:
            date, compress = m.groups()
            if (date > log_date) or (date == log_date and compress is None):
                log_file_path, log_date, log_compress = filename, date, compress

    if log_file_path:
        log_file_path = os.path.join(log_dir_abs, log_file_path)
        log_date = datetime.strptime(log_date, '%Y%m%d')

    return log_file_path, log_date, log_compress


def log_data_generator(open_file, log_compress=None):
    """

    :param open_file: file object
    :param log_compress: str
    :return: request_url: str
    :return: request_time: float
    """
    url_pattern = '"[A-Z]+\\s([^\\s]+)'
    time_pattern = '([\\.\\d]+)$'

    for line in open_file:
        line = line.decode('utf-8') if log_compress else line
        line = line.strip()
        request_url = re.search(url_pattern, line).groups()[0]
        request_time = re.search(time_pattern, line).groups()[0]
        request_time = float(request_time)

        yield request_url, request_time


def calculate_json_table(aggregated_data, total_request_time, total_count, report_size):
    """

    :param aggregated_data: dict
    :param total_request_time: float
    :param total_count: int
    :param report_size: int
    :return:
    """
    table = list()
    for url, time_list in aggregated_data.items():
        url_data = dict()

        url_data['url'] = url
        url_data['count'] = len(time_list)
        url_data['time_max'] = max(time_list)
        url_data['time_sum'] = sum(time_list)
        url_data['time_avg'] = url_data['time_sum'] / url_data['count']
        url_data['time_perc'] = 100 * url_data['time_sum'] / total_request_time
        url_data['count_perc'] = 100 * url_data['count'] / total_count
        middle = url_data['count'] // 2
        if url_data['count'] % 2 != 0:
            url_data['time_med'] = sorted(time_list)[middle]
        else:
            url_data['time_med'] = sum(sorted(time_list)[middle - 1:middle + 1]) / 2

        table.append(url_data)

    sorted_table = sorted(table, key=lambda d: d['time_sum'], reverse=True)[:report_size]


def aggregate_log_data(data):
    """

    :param data: generator object
        tuple: request_url, request_time
    :return:
    """
    total_count = 0
    total_request_time = float()
    aggregated_data = defaultdict(list)
    for request_url, request_time in data:
        aggregated_data[request_url].append(request_time)
        total_request_time += request_time
        total_count += 1


def get_log_report(conf):
    """

    :param conf: dict
    :return:
    """
    log_file_path, log_date, log_compress = get_last_log_file(conf['LOG_DIR'], conf['LOG_PATTERN'])

    open_file = gzip.open(log_file_path, 'rb') if log_compress else open(log_file_path, 'r')
    data = log_data_generator(open_file, log_compress)


def main():
    get_log_report(config)


if __name__ == "__main__":
    main()
