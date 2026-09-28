import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

import server


class ConsentTests(unittest.TestCase):
    def test_authorization_requests_180_days(self):
        handler = object.__new__(server.MetricsHandler)
        handler.path = "/auth?bank=0"
        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()
        cfg = {
            "api": {"origin": "https://api.example.test"},
            "banks": [{"name": "Example Bank", "country": "ES"}],
        }
        application = Mock(status_code=200)
        application.json.return_value = {"redirect_urls": ["https://example.test/callback"]}
        authorization = Mock(status_code=200)
        authorization.json.return_value = {"url": "https://example.test/authorize"}

        with (
            patch.object(server, "load_config", return_value=cfg),
            patch.object(server, "create_jwt_token", return_value="test-jwt"),
            patch.object(server.requests, "get", return_value=application),
            patch.object(server.requests, "post", return_value=authorization) as post,
        ):
            before = datetime.now(timezone.utc)
            handler.do_GET()
            after = datetime.now(timezone.utc)

        validity = datetime.fromisoformat(post.call_args.kwargs["json"]["access"]["valid_until"])
        self.assertLessEqual(before + timedelta(days=180), validity)
        self.assertLessEqual(validity, after + timedelta(days=180))
        handler.send_response.assert_called_once_with(302)
        handler.send_header.assert_called_once_with(
            "Location", "https://example.test/authorize"
        )

    def test_expired_consent_does_not_attempt_unsupported_renewal(self):
        cfg = {"api": {"origin": "https://api.example.test"}}
        session = {
            "session_id": "test-session",
            "aspsp": {"name": "Example Bank", "country": "ES"},
            "accounts": ["test-account"],
        }
        current = Mock(status_code=200)
        current.json.return_value = session
        expired = Mock(status_code=401)

        with (
            patch.object(server, "load_config", return_value=cfg),
            patch.object(server, "create_jwt_token", return_value="test-jwt"),
            patch.object(server, "load_session", return_value={"Example Bank_ES": session}),
            patch.object(server.requests, "get", side_effect=[current, expired]),
            patch.object(server.requests, "put") as put,
        ):
            server.scrape_balances()

        put.assert_not_called()
        self.assertFalse(server.state.balances)


if __name__ == "__main__":
    unittest.main()
