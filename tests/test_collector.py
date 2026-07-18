import unittest

from ueba_detector.collector import (
    parse_duration,
    process_stats_from_ps_output,
    tcp_stats_from_lsof_output,
    tcp_stats_from_netstat_output,
)


class CollectorTests(unittest.TestCase):
    def test_parse_duration(self):
        self.assertEqual(parse_duration("2h"), 7200)
        self.assertEqual(parse_duration("30m"), 1800)
        self.assertEqual(parse_duration("5s"), 5)

    def test_tcp_stats_from_lsof_output(self):
        output = (
            "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
            "Python  11  max  5u IPv4 0x1      0t0  TCP 127.0.0.1:5000->127.0.0.1:6000 (ESTABLISHED)\n"
            "Python  12  max  6u IPv4 0x2      0t0  TCP *:8080 (LISTEN)\n"
            "Python  13  max  7u IPv4 0x3      0t0  TCP 10.0.0.1:4444->93.184.216.34:443 (SYN_SENT)\n"
        )
        stats = tcp_stats_from_lsof_output(output)
        self.assertEqual(stats["tcp_established"], 1)
        self.assertEqual(stats["tcp_listen"], 1)
        self.assertEqual(stats["tcp_syn_sent"], 1)
        self.assertEqual(stats["unique_remote_ports"], 2)

    def test_process_stats_from_ps_output(self):
        output = "USER PID THCOUNT\nmax 1 5\nroot 2 8\n"
        stats = process_stats_from_ps_output(output, current_user="max")
        self.assertEqual(stats["process_count"], 2)
        self.assertEqual(stats["user_process_count"], 1)
        self.assertEqual(stats["thread_count"], 13)

    def test_tcp_stats_from_netstat_output(self):
        output = (
            "Proto Local Address Foreign Address State PID\n"
            "TCP 127.0.0.1:5000 127.0.0.1:6000 ESTABLISHED 10\n"
            "TCP 0.0.0.0:8080 0.0.0.0:0 LISTENING 11\n"
            "TCP 10.0.0.1:4444 93.184.216.34:443 SYN_SENT 12\n"
        )
        stats = tcp_stats_from_netstat_output(output)
        self.assertEqual(stats["tcp_established"], 1)
        self.assertEqual(stats["tcp_listen"], 1)
        self.assertEqual(stats["tcp_syn_sent"], 1)
        self.assertEqual(stats["unique_remote_ports"], 2)


if __name__ == "__main__":
    unittest.main()
