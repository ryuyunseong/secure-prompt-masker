import unittest

from secure_prompt_masker import SecurePromptMaskerApp


class MaskingCoreTests(unittest.TestCase):
    def setUp(self):
        self.app = SecurePromptMaskerApp.__new__(SecurePromptMaskerApp)

    def test_masks_sensitive_http_fields(self):
        source = (
            "Authorization: Bearer DEMO_TOKEN_12345678\n"
            "Cookie: session=DEMO_SESSION_123; theme=light\n"
            "X-Api-Key: DEMO_API_KEY_123\n"
            "password=DEMO_PASSWORD_123\n"
        )

        result = self.app._mask_structured_sensitive(source)

        self.assertNotIn("DEMO_TOKEN_12345678", result)
        self.assertNotIn("DEMO_SESSION_123", result)
        self.assertNotIn("DEMO_API_KEY_123", result)
        self.assertNotIn("DEMO_PASSWORD_123", result)
        self.assertIn("theme=*****", result)

    def test_masks_json_xml_and_basic_auth_url(self):
        source = (
            '{"client_secret": "DEMO_SECRET_123", "message": "safe"}\n'
            "<password>DEMO_PASSWORD_123</password>\n"
            "https://demo-user:DEMO_PASSWORD_456@example.test/path"
        )

        result = self.app._mask_structured_sensitive(source)

        self.assertNotIn("DEMO_SECRET_123", result)
        self.assertNotIn("DEMO_PASSWORD_123", result)
        self.assertNotIn("DEMO_PASSWORD_456", result)
        self.assertIn('"message": "safe"', result)
        self.assertIn("demo-user:", result)

    def test_masks_only_selected_detected_values(self):
        source = "first=DEMO_VALUE_1 second=DEMO_VALUE_2"
        selected = {"가짜 분류": ["DEMO_VALUE_1"]}

        result = self.app._mask_sensitive_patterns(source, selected)

        self.assertNotIn("DEMO_VALUE_1", result)
        self.assertIn("DEMO_VALUE_2", result)

    def test_product_version_is_not_classified_as_ipv4(self):
        details = self.app._collect_sensitive_details_raw(
            "User-Agent: DemoBrowser/145.0.0.0"
        )

        self.assertNotIn("IPv4", details)

    def test_url_encoding_warns_that_it_is_not_masking(self):
        class InputTextStub:
            @staticmethod
            def get(_start, _end):
                return "message=DEMO VALUE"

        notices = []
        self.app.input_text = InputTextStub()
        self.app._replace_output_text = lambda _text: None
        self.app._copy_output_to_clipboard = lambda: None
        self.app._set_notice = lambda message, status=None: notices.append(
            (message, status)
        )

        self.app.url_encode()

        self.assertEqual(1, len(notices))
        self.assertTrue(notices[0][0].startswith("WARN:"))
        self.assertIn("민감정보를 숨기지 않습니다", notices[0][0])
        self.assertIn("마스킹되지 않음", notices[0][1])


if __name__ == "__main__":
    unittest.main()
