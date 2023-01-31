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
from string import Template

config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "../data/reports",
    "LOG_DIR": "../data/log",
    "TEMPLATE": "../static/report.html",
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
    log_file_path = None
    log_date = 0
    log_compress = None

    for filename in os.listdir(log_dir):
        m = re.match(log_pattern, filename)
        if m is not None:
            date, compress = m.groups()
            date = int(date)
            if (date > log_date) or (date == log_date and compress is None):
                log_file_path, log_date, log_compress = filename, date, compress

    if log_file_path:
        log_file_path = os.path.join(log_dir, log_file_path)
        log_date = datetime.strptime(str(log_date), '%Y%m%d')

    return log_file_path, log_date, log_compress


def log_data_generator(open_file, log_compress=None):
    """

    :param open_file: file object
    :param log_compress: str
    :return: request_url: str
    :return: request_time: float
    """
    pattern = '"[A-Z]+\\s([^\\s]+).+?([\\.\\d]+)$'
    compile_pattern = re.compile(pattern)

    for line in open_file:
        line = line.decode('utf-8') if log_compress else line
        line = line.strip()
        request_url, request_time = None, None

        res = compile_pattern.search(line)
        if res is not None:
            request_url, request_time = res.groups()
            request_time = float(request_time)

        yield request_url, request_time


def calculate_json_table(aggregated_data, total_request_time, total_count, report_size):
    """

    :param aggregated_data: dict
    :param total_request_time: float
    :param total_count: int
    :param report_size: int
    :return: json_table: str(json)
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
        middle = url_data['count'] // 2
        if url_data['count'] % 2 != 0:
            url_data['time_med'] = round(sorted(time_list)[middle], 3)
        else:
            url_data['time_med'] = round(sum(sorted(time_list)[middle - 1:middle + 1]) / 2, 3)

        table.append(url_data)

    sorted_table = sorted(table, key=lambda d: d['time_sum'], reverse=True)[:report_size]
    json_table = json.dumps(sorted_table)
    return json_table


def rendering_report(table, template_path, report_path):
    """

    :param table: str(json)
    :param template_path: str(full path)
    :param report_path: str(full path)
    :return: None
    """
    with open(template_path, 'r') as tmpl:
        template_html = Template(tmpl.read())

    report_html = template_html.safe_substitute(table_json=table)

    with open(report_path, 'w') as report:
        report.write(report_html)


def aggregate_log_data(data):
    """

    :param data: generator object
        tuple: request_url, request_time
    :return: aggregated_data: dict
    :return: total_request_time: float
    :return: total_count: int
    """
    total_count = 0
    total_request_time = float()
    aggregated_data = defaultdict(list)
    for request_url, request_time in data:
        if (request_url is None) or (request_time is None):
            continue
        aggregated_data[request_url].append(request_time)
        total_request_time += request_time
        total_count += 1

    return aggregated_data, total_request_time, total_count


def get_log_report(conf):
    """

    :param conf: dict
    :return:
    """
    log_dir = os.path.abspath(conf['LOG_DIR'])
    template_path = os.path.abspath(conf['TEMPLATE'])

    log_file_path, date, compress = get_last_log_file(log_dir, conf['LOG_PATTERN'])

    open_file = gzip.open(log_file_path, 'rb') if compress else open(log_file_path, 'r')
    log_data = log_data_generator(open_file, compress)
    aggregated_data, total_request_time, total_count = aggregate_log_data(log_data)
    open_file.close()

    json_table = calculate_json_table(
        aggregated_data,
        total_request_time,
        total_count,
        conf['REPORT_SIZE']
    )

    report_path = os.path.join(
        os.path.abspath(conf['REPORT_DIR']),
        f'report-{date.strftime("%Y")}.{date.strftime("%m")}.{date.strftime("%d")}.html'
    )
    rendering_report(json_table, template_path, report_path)


def main():
    get_log_report(config)


if __name__ == "__main__":
    main()
