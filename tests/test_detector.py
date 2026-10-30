import unittest
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from detector import ScamDetector

class TestScamDetector(unittest.TestCase):
    def setUp(self):
        self.detector = ScamDetector()

    def test_normal_message(self):
        msg = "Hey mom, I will be home by 6 PM for dinner."
        res = self.detector.analyze_message(msg)
        self.assertEqual(res['level'], 'Low')
        self.assertLess(res['score'], 25)

    def test_bank_scam_message(self):
        msg = "URGENT ACTION REQUIRED: Your bank account is locked. Verify your account immediately."
        res = self.detector.analyze_message(msg)
        self.assertIn(res['level'], ['Medium', 'High', 'Critical'])
        self.assertGreaterEqual(res['score'], 20)

    def test_lottery_scam(self):
        msg = "Congratulations! You have won $1,000,000 in a lottery winner draw. Claim your prize."
        res = self.detector.analyze_message(msg)
        self.assertGreaterEqual(res['score'], 25)

    def test_otp_theft(self):
        msg = "Send your OTP and password code to our customer support officer immediately."
        res = self.detector.analyze_message(msg)
        self.assertGreaterEqual(res['score'], 30)

    test_suspicious_url = lambda self: self.assertGreaterEqual(
        self.detector.analyze_message("Click here: http://192.168.1.1/paypal-verify")['score'], 25
    )

    def test_empty_input(self):
        res = self.detector.analyze_message("")
        self.assertEqual(res['score'], 0)
        self.assertEqual(res['level'], 'Low')

    def test_long_input(self):
        long_msg = "Safe text " * 500
        res = self.detector.analyze_message(long_msg)
        self.assertEqual(res['level'], 'Low')

if __name__ == '__main__':
    unittest.main()
