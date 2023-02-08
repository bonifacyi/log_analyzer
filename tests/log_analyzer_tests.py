#!/usr/bin/env python

import unittest
import re
import json
from log_analyzer import log_analyzer

'''list_dir = [
            'nginx-access-ui.log-20200630.zip',
            'nginx-access-ui.log-20200630.123abc.gz',
            'nginx-access-ui.log-20200630123abc.gz',
            'abc123nginx-access-ui.log-20200630.gz',
            'nginx-access-ui.log-20170630.gz',
]
ans = log_analyzer.get_last_log_file('log', list_dir, log_analyzer.config["LOG_PATTERN"])
print(ans)'''


class LogAnalyzerTestCase(unittest.TestCase):
    """

    """
    def test_finding_last_log_file(self):
        """

        :return:
        """
        list_dir = [
            'nginx-access-ui.log-20200630.zip',
            'nginx-access-ui.log-20200630.123abc.gz',
            'nginx-access-ui.log-20200630123abc',
            'abc123nginx-access-ui.log-20200630',
            'nginx-access-ui.log-20170630.gz',
        ]

        log_meta = log_analyzer.get_last_log_file(
            'log',
            list_dir,
            log_analyzer.config["LOG_FILENAME_PATTERN"]
        )

        self.assertEqual(log_meta.log_file_path, 'log/nginx-access-ui.log-20170630.gz')
        self.assertEqual(log_meta.year, '2017')
        self.assertEqual(log_meta.month, '06')
        self.assertEqual(log_meta.day, '30')
        self.assertEqual(log_meta.compress, 'gz')

    def test_find_metrics_in_log_msg(self):
        """

        :return:
        """
        msg = '5.6.7.8 -  c8 [2/J/7:3 +3] "POST /a.1/b2/c/?d&e=WIN H/1.1" 200 22 "-" "p" 2.654'
        compiled_pattern = re.compile(log_analyzer.config["LOG_MSG_PATTERN"])
        url, time = log_analyzer.find_metrics_in_log_msg(compiled_pattern, msg)
        self.assertEqual(url, '/a.1/b2/c/?d&e=WIN')
        self.assertEqual(time, 2.654)

    def test_calculate_json_table(self):
        """

        :return:
        """
        data = {
            'a/b/1': [1.0, 2.0, 5.0],
            'a/b/2': [1.0, 2.0, 5.0, 10.0],
            'a/b/3': [4.0, 2.0, 4.0, 2.0],
            'a/b/4': [10.0, 5.0, 20.0, 15.0, 20.0],
        }
        json_table = log_analyzer.calculate_json_table(
            data,
            sum([sum(t) for t in data.values()]),
            sum([len(t) for t in data.values()]),
            2
        )
        table = json.loads(json_table)

        self.assertDictEqual(
            table[0],
            {'url': 'a/b/4', 'count': 5, 'time_max': 20.0, 'time_sum': 70.0,
             'time_avg': 14.0, 'time_perc': 64.815, 'count_perc': 31.25, 'time_med': 15.0}
        )
        self.assertDictEqual(
            table[1],
            {'url': 'a/b/2', 'count': 4, 'time_max': 10.0, 'time_sum': 18.0,
             'time_avg': 4.5, 'time_perc': 16.667, 'count_perc': 25.0, 'time_med': 3.5}
        )


if __name__ == '__main__':
    unittest.main()
