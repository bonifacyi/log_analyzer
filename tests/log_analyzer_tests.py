#!/usr/bin/env python

import unittest
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
            'nginx-access-ui.log-20200630123abc.gz',
            'abc123nginx-access-ui.log-20200630.gz',
            'nginx-access-ui.log-20170630.gz',
        ]

        log_meta = log_analyzer.get_last_log_file(
            'log',
            list_dir,
            log_analyzer.config["LOG_PATTERN"]
        )

        self.assertEqual(log_meta.log_file_path, 'log/nginx-access-ui.log-20200630.gz')
        self.assertEqual(log_meta.year, '2017')
        self.assertEqual(log_meta.month, '06')
        self.assertEqual(log_meta.day, '30')
        self.assertEqual(log_meta.compress, '.gz')
