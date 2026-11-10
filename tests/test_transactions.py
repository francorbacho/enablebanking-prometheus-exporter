import json
import os
import tempfile
import unittest
from datetime import date
from unittest.mock import Mock, patch

import server


def response(body, status_code=200):
    r = Mock(status_code=status_code)
    r.json.return_value = body
    return r


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = {
            "api": {"origin": "https://api.example.test"},
            "banks": [{"name": "Example Bank", "country": "ES"}],
            "server": {"transactions_days": 90},
            "session_file": os.path.join(self.tmp.name, "session.json"),
        }
        self.session = {
            "session_id": "test-session",
            "aspsp": {"name": "Example Bank", "country": "ES"},
            "access": {"valid_until": "2027-05-01T00:00:00+00:00"},
            "accounts": [
                {
                    "uid": "acc-1",
                    "name": "Main <account>",
                    "account_id": {"iban": "ES0000000000000000000001"},
                }
            ],
        }
        server.state = server.AppState()

    def tearDown(self):
        self.tmp.cleanup()

    def test_fetches_recent_week_after_latest_stored_transaction(self):
        stored = [{"booking_date": "2026-10-01"}, {"booking_date": "2026-11-08"}]
        self.assertEqual(
            server.transactions_since(stored, date(2026, 11, 10), 90), date(2026, 11, 1)
        )
        self.assertEqual(
            server.transactions_since([], date(2026, 11, 10), 90), date(2026, 8, 12)
        )
        self.assertEqual(
            server.transactions_since(
                [{"booking_date": "2026-01-01"}], date(2026, 11, 10), 90
            ),
            date(2026, 8, 12),
        )

    def test_refetched_window_replaces_pending_transactions(self):
        stored = [
            {"booking_date": "2026-10-01", "entry_reference": "old"},
            {"transaction_date": "2026-11-05", "status": "PDNG"},
        ]
        fetched = [{"booking_date": "2026-11-05", "status": "BOOK"}]
        merged = server.merge_transactions(stored, fetched, date(2026, 11, 1))
        self.assertEqual(merged, [stored[0], fetched[0]])

    def test_scrape_stores_all_transaction_pages(self):
        pages = [
            response(
                {
                    "transactions": [
                        {
                            "booking_date": "2026-11-02",
                            "credit_debit_indicator": "DBIT",
                            "transaction_amount": {"amount": "12.50", "currency": "EUR"},
                            "creditor": {"name": "Shop"},
                            "remittance_information": ["Groceries"],
                        }
                    ],
                    "continuation_key": "next",
                }
            ),
            response(
                {
                    "transactions": [
                        {
                            "booking_date": "2026-11-01",
                            "credit_debit_indicator": "CRDT",
                            "transaction_amount": {"amount": "1000", "currency": "EUR"},
                            "debtor": {"name": "Employer"},
                        }
                    ]
                }
            ),
        ]
        balances = response(
            {
                "balances": [
                    {
                        "balance_type": "ITAV",
                        "balance_amount": {"amount": "42.00", "currency": "EUR"},
                    }
                ]
            }
        )
        current = response({**self.session, "accounts": ["acc-1"]})

        with (
            patch.object(server, "load_config", return_value=self.cfg),
            patch.object(server, "create_jwt_token", return_value="test-jwt"),
            patch.object(
                server, "load_session", return_value={"Example Bank_ES": self.session}
            ),
            patch.object(
                server.requests, "get", side_effect=[current, balances, *pages]
            ) as get,
        ):
            server.scrape_balances(transactions=True)
            page = server.format_status()

        self.assertEqual(get.call_args.kwargs["params"]["continuation_key"], "next")
        with open(os.path.join(self.tmp.name, "transactions.json")) as f:
            stored = json.load(f)
        rows = server.transaction_rows(stored)
        self.assertEqual(
            [(r["date"], r["amount"], r["counterparty"]) for r in rows],
            [("2026-11-02", -12.5, "Shop"), ("2026-11-01", 1000.0, "Employer")],
        )
        self.assertTrue(
            server.transactions_csv(rows).startswith(
                "date,bank_name,account_uid,amount,currency,status,counterparty,description"
            )
        )
        self.assertIn("Active", page)
        self.assertIn("Main &lt;account&gt;", page)
        self.assertIn("ES0000000000000000000001", page)
        self.assertIn("42.00 EUR", page)

    def test_status_lists_banks_without_session(self):
        with (
            patch.object(server, "load_config", return_value=self.cfg),
            patch.object(server, "load_session", return_value={}),
        ):
            page = server.format_status()

        self.assertIn("Not connected", page)
        self.assertIn('href="/auth?bank=0"', page)


if __name__ == "__main__":
    unittest.main()
