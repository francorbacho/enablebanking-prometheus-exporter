import json
import os
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import server


def transaction(reference, day, amount):
    return {
        "entry_reference": reference,
        "booking_date": day,
        "credit_debit_indicator": "DBIT",
        "transaction_amount": {"amount": amount, "currency": "EUR"},
    }


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        key_path = os.path.join(self.tmp.name, "key.pem")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(key_path, "wb") as f:
            f.write(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
        self.cfg = {
            "api": {"application_id": "app-id", "key_path": key_path},
            "banks": [
                {"name": "Revolut", "country": "ES"},
                {"name": "Lunar", "country": "DK"},
            ],
            "session_file": os.path.join(self.tmp.name, "session.json"),
        }
        with open(os.path.join(self.tmp.name, "transactions.json"), "w") as f:
            json.dump(
                {
                    "old-uid": {
                        "bank_name": "Revolut",
                        "bank_country": "ES",
                        "iban": "ES1",
                        "currency": "EUR",
                        "transactions": [
                            transaction("r1", "2026-10-01", "1.00"),
                            transaction("r2", "2026-11-01", "2.00"),
                        ],
                    },
                    "new-uid": {
                        "bank_name": "Revolut",
                        "bank_country": "ES",
                        "iban": "ES1",
                        "currency": "EUR",
                        "transactions": [
                            transaction("r2", "2026-11-01", "2.00"),
                            transaction("r3", "2026-11-05", "3.00"),
                        ],
                    },
                },
                f,
            )
        server.state = server.AppState()
        server.state.banks = {
            "Revolut_ES": {
                "bank_name": "Revolut",
                "bank_country": "ES",
                "error": None,
                "accounts": [
                    {"uid": "new-uid", "name": "Main", "iban": "ES1", "currency": "EUR"}
                ],
            }
        }
        self.balances = [
            {"balance_type": "ITAV", "balance_amount": {"amount": "10.00", "currency": "EUR"}}
        ]
        server.state.balances = {"Revolut_ES:new-uid": {"balances": self.balances}}
        self.patches = [
            patch.object(server, "load_config", return_value=self.cfg),
            patch.object(server, "load_session", return_value={"Revolut_ES": {}}),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def call(self, method, path, query=None, body=None, token=None):
        token = token or f"Bearer {server.create_jwt_token(self.cfg)}"
        return server.handle_api(method, path, query or {}, body or {}, token)

    def test_rejects_tokens_not_signed_by_the_application(self):
        for token in [None, "Bearer nonsense"]:
            with self.assertRaises(server.ApiError) as error:
                server.handle_api("GET", "/application", {}, {}, token)
            self.assertEqual(error.exception.status, 401)

        other = {**self.cfg, "api": {**self.cfg["api"], "application_id": "other"}}
        with self.assertRaises(server.ApiError) as error:
            self.call("GET", "/application", token=f"Bearer {server.create_jwt_token(other)}")
        self.assertEqual(error.exception.status, 401)

    def test_links_an_authorized_bank_without_a_new_consent(self):
        self.assertEqual(
            [a["name"] for a in self.call("GET", "/aspsps", {"country": ["ES"]})["aspsps"]],
            ["Revolut"],
        )
        self.assertEqual(self.call("GET", "/aspsps", {"country": ["DK"]})["aspsps"], [])
        with self.assertRaises(server.ApiError):
            self.call("POST", "/auth", body={"aspsp": {"name": "Lunar", "country": "DK"}})

        auth = self.call(
            "POST",
            "/auth",
            body={
                "aspsp": {"name": "Revolut", "country": "ES"},
                "redirect_url": "https://actual.example/enablebanking/auth_callback",
                "state": "abc",
            },
        )
        url = urlparse(auth["url"])
        self.assertEqual(url.netloc, "actual.example")
        params = parse_qs(url.query)
        self.assertEqual(params["state"], ["abc"])

        session = self.call("POST", "/sessions", body={"code": params["code"][0]})
        [account] = session["accounts"]
        self.assertEqual(account["account_id"], {"iban": "ES1"})
        self.assertEqual(account["currency"], "EUR")
        self.assertEqual(account["name"], "Revolut EUR")
        self.assertEqual(account["uid"], server.linked_account_id("Revolut", "ES1", "EUR", "x"))
        self.assertEqual(self.call("GET", f"/sessions/{session['session_id']}"), session)
        with self.assertRaises(server.ApiError):
            self.call("POST", "/sessions", body={"code": params["code"][0]})

    def test_serves_transactions_of_every_authorization_once(self):
        account_id = server.linked_account_id("Revolut", "ES1", "EUR", "x")
        result = self.call(
            "GET", f"/accounts/{account_id}/transactions", {"date_from": ["2026-10-15"]}
        )
        self.assertEqual(
            [t["entry_reference"] for t in result["transactions"]], ["r3", "r2"]
        )
        everything = self.call("GET", f"/accounts/{account_id}/transactions")
        self.assertEqual(
            [t["entry_reference"] for t in everything["transactions"]], ["r3", "r2", "r1"]
        )
        self.assertEqual(
            self.call("GET", f"/accounts/{account_id}/balances"),
            {"balances": self.balances},
        )

        server.state.banks = {}
        server.state.balances = {}
        [account] = self.call("GET", "/sessions/Revolut_ES")["accounts"]
        self.assertEqual(account["uid"], account_id)
        self.assertEqual(self.call("GET", f"/accounts/{account_id}/balances"), {"balances": []})
        with self.assertRaises(server.ApiError) as error:
            self.call("GET", "/accounts/unknown/balances")
        self.assertEqual(error.exception.status, 404)


if __name__ == "__main__":
    unittest.main()
