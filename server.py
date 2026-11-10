#!/usr/bin/env python3
"""
EnableBanking Prometheus Exporter

An HTTP server that scrapes account balances from banks via EnableBanking API
and exposes them via a /metrics endpoint in Prometheus format.
"""

import csv
import html
import io
import json
import logging
import os
import ssl
import sys
import threading
import time
from datetime import date, datetime, timezone, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional
import uuid
from urllib.parse import urlencode, urlparse, parse_qs

import jwt as pyjwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import requests
import yaml


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

CONFIG_FILES = ["./config.yml", "/app/config.yml"]

# Global configuration and state
config = None


class AppState:
    def __init__(self):
        self.balances: Dict[str, List[Dict]] = {}
        self.banks: Dict[str, Dict] = {}
        self.last_scrape_time: Optional[float] = None
        self.last_transactions_time: Optional[float] = None
        self.link_codes: Dict[str, Dict] = {}
        self.scrape_error: Optional[str] = None
        self.pending_auth_state: Optional[str] = None
        self.pending_bank_index: Optional[int] = (
            None  # Track which bank is being authed
        )
        self.lock = threading.Lock()


state = AppState()


def load_config():
    """Load configuration from config.yml"""
    global config
    if config is None:
        for config_file in CONFIG_FILES:
            if os.path.exists(config_file):
                logger.info(f"Loading configuration from {config_file}")
                with open(config_file, "r") as f:
                    config = yaml.safe_load(f)
                return config
        raise FileNotFoundError(
            f"Configuration file not found. Tried: {', '.join(CONFIG_FILES)}"
        )
    return config


def load_session():
    """Load saved sessions from session.json"""
    cfg = load_config()
    session_file = cfg["session_file"]
    if os.path.exists(session_file):
        with open(session_file, "r") as f:
            data = json.load(f)
            # Handle both old format (single session) and new format (dict of sessions)
            if "sessions" in data:
                return data["sessions"]
            elif "session_id" in data:
                # Migrate old format: single session to new multi-bank format
                bank_key = f"{data.get('aspsp', {}).get('name', 'unknown')}_{data.get('aspsp', {}).get('country', 'unknown')}"
                return {bank_key: data}
    return {}


def save_session(bank_name, bank_country, session):
    """Save session for a specific bank"""
    cfg = load_config()
    session_file = cfg["session_file"]

    # Load existing sessions
    sessions = load_session()

    # Add/update this bank's session
    bank_key = f"{bank_name}_{bank_country}"
    sessions[bank_key] = session

    # Save back to file
    with open(session_file, "w") as f:
        json.dump({"sessions": sessions}, f, indent=2)
    logger.info(f"Session saved for {bank_name} ({bank_country}) to {session_file}")


def transactions_file(cfg):
    return cfg.get("transactions_file") or os.path.join(
        os.path.dirname(cfg["session_file"]), "transactions.json"
    )


def load_transactions(cfg):
    """Load stored transactions, keyed by account UID"""
    path = transactions_file(cfg)
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return {}


def save_transactions(cfg, transactions):
    path = transactions_file(cfg)
    with open(f"{path}.tmp", "w") as f:
        json.dump(transactions, f, indent=2)
    os.replace(f"{path}.tmp", path)


def transaction_date(transaction):
    return (
        transaction.get("booking_date")
        or transaction.get("value_date")
        or transaction.get("transaction_date")
        or ""
    )


def transactions_since(stored, today, days):
    """First day to fetch: a week before the latest stored transaction, within the allowed history"""
    earliest = today - timedelta(days=days)
    dates = [transaction_date(t) for t in stored if transaction_date(t)]
    if not dates:
        return earliest
    return max(earliest, date.fromisoformat(max(dates)) - timedelta(days=7))


def merge_transactions(stored, fetched, since):
    """Replace stored transactions from `since` onwards with freshly fetched ones"""
    older = [t for t in stored if transaction_date(t) < since.isoformat()]
    return older + fetched


def fetch_transactions(api_origin, headers, account_uid, since):
    transactions = []
    params = {"date_from": since.isoformat()}
    while True:
        r = requests.get(
            f"{api_origin}/accounts/{account_uid}/transactions",
            headers=headers,
            params=params,
        )
        if r.status_code != 200:
            raise Exception(
                f"Error fetching transactions for {account_uid}: {r.status_code} - {r.text}"
            )
        data = r.json()
        transactions.extend(data.get("transactions") or [])
        if not data.get("continuation_key"):
            return transactions
        params["continuation_key"] = data["continuation_key"]


def transaction_rows(stored):
    """Flatten stored transactions, signed negative for money going out, newest first"""
    rows = []
    for account_uid, account in stored.items():
        for t in account.get("transactions", []):
            amount = t.get("transaction_amount") or {}
            value = float(amount.get("amount") or 0)
            indicator = t.get("credit_debit_indicator")
            if indicator == "DBIT":
                value = -abs(value)
            elif indicator == "CRDT":
                value = abs(value)
            counterparty = (t.get("creditor") if value < 0 else t.get("debtor")) or {}
            rows.append(
                {
                    "date": transaction_date(t),
                    "bank_name": account.get("bank_name", ""),
                    "account_uid": account_uid,
                    "amount": value,
                    "currency": amount.get("currency", ""),
                    "status": t.get("status", ""),
                    "counterparty": counterparty.get("name") or "",
                    "description": " ".join(t.get("remittance_information") or []),
                }
            )
    rows.sort(key=lambda row: row["date"], reverse=True)
    return rows


def transactions_csv(rows):
    out = io.StringIO()
    writer = csv.DictWriter(
        out,
        fieldnames=[
            "date",
            "bank_name",
            "account_uid",
            "amount",
            "currency",
            "status",
            "counterparty",
            "description",
        ],
    )
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue()


def account_info(saved_session):
    """Account names and IBANs, as returned when the session was authorized"""
    info = {}
    for account in saved_session.get("accounts", []):
        if isinstance(account, dict) and account.get("uid"):
            info[account["uid"]] = {
                "name": account.get("name") or account.get("product") or "",
                "iban": (account.get("account_id") or {}).get("iban") or "",
                "currency": account.get("currency") or "",
            }
    return info


def create_jwt_token(cfg):
    """Create JWT token for API authentication"""
    iat = int(datetime.now().timestamp())
    jwt_body = {
        "iss": "enablebanking.com",
        "aud": "api.enablebanking.com",
        "iat": iat,
        "exp": iat + 3600,
    }
    jwt = pyjwt.encode(
        jwt_body,
        open(cfg["api"]["key_path"], "rb").read(),
        algorithm="RS256",
        headers={"kid": cfg["api"]["application_id"]},
    )
    return jwt


def get_or_create_session(cfg, jwt_token, bank_name=None, bank_country=None):
    """Get existing session for a specific bank"""
    sessions = load_session()

    # If bank not specified, try to find any valid session
    if bank_name is None or bank_country is None:
        if not sessions:
            raise Exception(
                "No valid session found. Please authenticate by visiting /auth"
            )
        # Use the first available session
        bank_key = next(iter(sessions.keys()))
        saved_session = sessions[bank_key]
    else:
        bank_key = f"{bank_name}_{bank_country}"
        if bank_key not in sessions:
            raise Exception(
                f"No session found for {bank_name} ({bank_country}). Please authenticate at /auth"
            )
        saved_session = sessions[bank_key]

    if "session_id" not in saved_session:
        raise Exception("Invalid session format")

    base_headers = {"Authorization": f"Bearer {jwt_token}"}
    session_id = saved_session["session_id"]
    api_origin = cfg["api"]["origin"]

    r = requests.get(f"{api_origin}/sessions/{session_id}", headers=base_headers)
    if r.status_code == 200:
        session_data = r.json()
        # Use API response if it has accounts, otherwise fall back to saved session
        session = session_data if "accounts" in session_data else saved_session
        logger.info(f"Using valid session for {bank_key}")
        return session

    raise Exception(
        f"Session invalid for {bank_key} (status {r.status_code}). Please re-authenticate at /auth"
    )


def scrape_balances(transactions=False):
    """Scrape account balances, and optionally transactions, from all configured banks"""
    try:
        print(f"[{datetime.now().isoformat()}] Starting balance scrape...")

        cfg = load_config()
        jwt_token = create_jwt_token(cfg)
        base_headers = {"Authorization": f"Bearer {jwt_token}"}
        api_origin = cfg["api"]["origin"]

        sessions = load_session()
        if not sessions:
            raise Exception("No sessions found. Please authenticate at /auth")

        new_balances = {}
        new_banks = {}
        if transactions:
            stored_transactions = load_transactions(cfg)
            history_days = cfg["server"].get("transactions_days", 90)

        # Scrape each bank's accounts
        for bank_key, saved_session in sessions.items():
            bank_status = new_banks[bank_key] = {
                "error": None,
                "valid_until": (saved_session.get("access") or {}).get("valid_until"),
                "accounts": [],
            }
            try:
                bank_name = saved_session.get("aspsp", {}).get("name", "unknown")
                bank_country = saved_session.get("aspsp", {}).get("country", "unknown")

                session = get_or_create_session(cfg, jwt_token, bank_name, bank_country)
                bank_status["valid_until"] = (session.get("access") or {}).get(
                    "valid_until", bank_status["valid_until"]
                )
                accounts = account_info(saved_session)

                if not session.get("accounts"):
                    logger.warning(f"No accounts found for {bank_key}")
                    continue

                bank_status["bank_name"] = bank_name
                bank_status["bank_country"] = bank_country
                for account in session["accounts"]:
                    account_uid = account["uid"] if isinstance(account, dict) else account
                    details = {
                        "uid": account_uid,
                        "name": "",
                        "iban": "",
                        "currency": "",
                        **accounts.get(account_uid, {}),
                    }
                    bank_status["accounts"].append(details)
                    logger.debug(
                        f"Fetching balance for account {account_uid} ({bank_key})"
                    )
                    r = requests.get(
                        f"{api_origin}/accounts/{account_uid}/balances",
                        headers=base_headers,
                    )

                    if r.status_code == 200:
                        balances_response = r.json()
                        # Include bank info in the key
                        account_key = f"{bank_key}:{account_uid}"
                        new_balances[account_key] = {
                            "balances": balances_response.get("balances", []),
                            "bank_name": bank_name,
                            "bank_country": bank_country,
                            "account_uid": account_uid,
                        }
                        if not details["currency"]:
                            details["currency"] = next(
                                (
                                    b["balance_amount"].get("currency", "")
                                    for b in new_balances[account_key]["balances"]
                                    if b.get("balance_amount")
                                ),
                                "",
                            )
                        logger.debug(
                            f"Retrieved {len(new_balances[account_key]['balances'])} balance(s) for {bank_key}"
                        )
                    elif r.status_code == 401:
                        bank_status["error"] = "Session expired. Please re-authenticate at /auth"
                        logger.error(f"Session expired for {bank_key}. Please re-authenticate at /auth")
                        continue
                    else:
                        bank_status["error"] = f"Error fetching balance: {r.status_code}"
                        logger.error(
                            f"Error fetching balance for {account_uid}: {r.status_code} - {r.text}"
                        )

                    if transactions:
                        try:
                            stored = stored_transactions.get(account_uid, {}).get(
                                "transactions", []
                            )
                            since = transactions_since(stored, date.today(), history_days)
                            fetched = fetch_transactions(
                                api_origin, base_headers, account_uid, since
                            )
                            stored_transactions[account_uid] = {
                                "bank_name": bank_name,
                                "bank_country": bank_country,
                                "name": details["name"],
                                "iban": details["iban"],
                                "currency": details["currency"],
                                "transactions": merge_transactions(stored, fetched, since),
                            }
                        except Exception as e:
                            bank_status["error"] = str(e)
                            logger.error(str(e))
            except Exception as e:
                bank_status["error"] = str(e)
                logger.error(f"Error scraping {bank_key}: {str(e)}")
                continue

        if transactions:
            save_transactions(cfg, stored_transactions)

        # Update state
        with state.lock:
            state.balances = new_balances
            state.banks = new_banks
            if transactions:
                state.last_transactions_time = time.time()
            state.last_scrape_time = time.time()
            state.scrape_error = None

        logger.info("Balance scrape completed successfully")
    except Exception as e:
        error_msg = f"Error scraping balances: {str(e)}"
        logger.error(error_msg)
        with state.lock:
            state.scrape_error = error_msg


def scrape_loop():
    """Background thread that scrapes balances every 2 hours"""
    cfg = load_config()
    interval_seconds = cfg["server"]["scrape_interval_hours"] * 3600
    transactions_interval = cfg["server"].get("transactions_interval_hours", 6) * 3600

    while True:
        last = state.last_transactions_time
        scrape_balances(
            transactions=last is None or time.time() - last >= transactions_interval
        )
        logger.info(
            f"Next scrape in {interval_seconds} seconds ({interval_seconds / 3600} hours)"
        )
        time.sleep(interval_seconds)


def format_metrics():
    """Format balances data as Prometheus metrics"""
    with state.lock:
        if not state.balances and state.scrape_error:
            return f"# Error: {state.scrape_error}\n"

        lines = []
        lines.append(
            "# HELP enablebanking_account_balance Account balance in the specified currency"
        )
        lines.append("# TYPE enablebanking_account_balance gauge")

        for account_key, account_data in state.balances.items():
            bank_name = account_data["bank_name"]
            bank_country = account_data["bank_country"]
            account_uid = account_data["account_uid"]

            for balance in account_data["balances"]:
                balance_amount_data = balance.get("balance_amount", {})
                currency = balance_amount_data.get("currency", "UNKNOWN")
                amount = balance_amount_data.get("amount", "0")
                balance_type = balance.get("balance_type", "UNKNOWN")

                # Create Prometheus metric with bank info
                labels = f'bank_name="{bank_name}",bank_country="{bank_country}",account_uid="{account_uid}",currency="{currency}",balance_type="{balance_type}"'
                lines.append(f"enablebanking_account_balance{{{labels}}} {amount}")

        lines.append("")
        lines.append(
            "# HELP enablebanking_scrape_timestamp_seconds Timestamp of last successful scrape"
        )
        lines.append("# TYPE enablebanking_scrape_timestamp_seconds gauge")
        if state.last_scrape_time:
            lines.append(
                f"enablebanking_scrape_timestamp_seconds {state.last_scrape_time}"
            )

        lines.append("")
        lines.append(
            "# HELP enablebanking_scrape_success Whether the last scrape was successful"
        )
        lines.append("# TYPE enablebanking_scrape_success gauge")
        lines.append(
            f"enablebanking_scrape_success {1 if not state.scrape_error else 0}"
        )

        return "\n".join(lines) + "\n"


def format_time(timestamp):
    if not timestamp:
        return "never"
    return datetime.fromtimestamp(timestamp).isoformat(sep=" ", timespec="minutes")


def format_status():
    """Render configured banks and their accounts as a plain HTML page"""
    cfg = load_config()
    sessions = load_session()
    stored = load_transactions(cfg)
    e = lambda value: html.escape(str(value or ""))

    with state.lock:
        banks = dict(state.banks)
        balances = dict(state.balances)
        last_scrape = state.last_scrape_time
        last_transactions = state.last_transactions_time
        scrape_error = state.scrape_error

    bank_rows = []
    account_rows = []
    for i, bank in enumerate(cfg["banks"]):
        bank_key = f"{bank['name']}_{bank['country']}"
        status = banks.get(bank_key)
        if bank_key not in sessions:
            text = "Not connected"
        elif status is None:
            text = "Waiting for first scrape"
        elif status["error"]:
            text = f"Error: {status['error']}"
        else:
            text = "Active"
        valid_until = (status or {}).get("valid_until") or (
            sessions.get(bank_key, {}).get("access") or {}
        ).get("valid_until")
        bank_rows.append(
            f"<tr><td>{e(bank['name'])}</td><td>{e(bank['country'])}</td><td>{e(text)}</td>"
            f"<td>{e(valid_until)}</td><td>{len((status or {}).get('accounts', []))}</td>"
            f'<td><a href="/auth?bank={i}">Authorize</a></td></tr>'
        )

        for account in (status or {}).get("accounts", []):
            amounts = [
                f"{b['balance_amount']['amount']} {b['balance_amount']['currency']}"
                for b in balances.get(f"{bank_key}:{account['uid']}", {}).get("balances", [])
                if b.get("balance_type") == "ITAV" and b.get("balance_amount")
            ]
            account_transactions = stored.get(account["uid"], {}).get("transactions", [])
            latest = max((transaction_date(t) for t in account_transactions), default="")
            account_rows.append(
                f"<tr><td>{e(bank['name'])}</td><td>{e(account.get('name'))}</td>"
                f"<td>{e(account.get('iban'))}</td><td><code>{e(account['uid'])}</code></td>"
                f"<td>{e(', '.join(amounts))}</td><td>{len(account_transactions)}</td><td>{e(latest)}</td></tr>"
            )

    error = f"<p><b>Error:</b> {e(scrape_error)}</p>" if scrape_error else ""
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>EnableBanking exporter</title>
<style>body{{font-family:sans-serif;margin:2em}}table{{border-collapse:collapse}}td,th{{border:1px solid #ccc;padding:4px 8px;text-align:left}}</style>
</head><body>
<h1>EnableBanking exporter</h1>
<p>Last balance scrape: {e(format_time(last_scrape))} &middot; Last transactions scrape: {e(format_time(last_transactions))}</p>
{error}
<p><a href="/metrics">Metrics</a> &middot; <a href="/transactions">Transactions (JSON)</a> &middot; <a href="/transactions.csv">Transactions (CSV)</a></p>
<h2>Banks</h2>
<table><tr><th>Bank</th><th>Country</th><th>Status</th><th>Consent until</th><th>Accounts</th><th></th></tr>
{''.join(bank_rows)}
</table>
<h2>Accounts</h2>
<table><tr><th>Bank</th><th>Name</th><th>IBAN</th><th>UID</th><th>Available balance</th><th>Transactions</th><th>Latest transaction</th></tr>
{''.join(account_rows)}
</table>
</body></html>
"""


class ApiError(Exception):
    def __init__(self, status, message, error="INVALID_REQUEST"):
        super().__init__(message)
        self.status = status
        self.payload = {"code": status, "message": message, "error": error}


def verify_api_token(cfg, authorization):
    """Accept tokens signed with this application's key, like Enable Banking does"""
    if not authorization or not authorization.startswith("Bearer "):
        raise ApiError(401, "Missing access token", "UNAUTHORIZED")
    token = authorization[len("Bearer ") :]
    with open(cfg["api"]["key_path"], "rb") as f:
        public_key = load_pem_private_key(f.read(), password=None).public_key()
    try:
        if pyjwt.get_unverified_header(token).get("kid") != cfg["api"]["application_id"]:
            raise ApiError(401, "Unknown application", "UNAUTHORIZED")
        pyjwt.decode(
            token, public_key, algorithms=["RS256"], audience="api.enablebanking.com"
        )
    except pyjwt.PyJWTError as e:
        raise ApiError(401, f"Invalid access token: {e}", "UNAUTHORIZED")


def linked_account_id(bank_name, iban, currency, uid):
    """An account ID that stays the same when a bank is re-authorized"""
    if not iban:
        return uid
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"enablebanking:{bank_name}:{iban}:{currency}"))


def linked_accounts(cfg):
    """Accounts of authorized banks, with every account UID they had and their latest balances"""
    with state.lock:
        banks = dict(state.banks)
        balances = dict(state.balances)
    accounts = {}
    for bank_key, status in banks.items():
        for account in status["accounts"]:
            account_id = linked_account_id(
                status.get("bank_name"), account["iban"], account["currency"], account["uid"]
            )
            entry = accounts.setdefault(
                account_id,
                {
                    "bank_key": bank_key,
                    "bank_name": status.get("bank_name"),
                    "bank_country": status.get("bank_country"),
                    "name": account["name"],
                    "iban": account["iban"],
                    "currency": account["currency"],
                    "uids": set(),
                    "balances": [],
                },
            )
            entry["uids"].add(account["uid"])
            entry["balances"] = balances.get(f"{bank_key}:{account['uid']}", {}).get(
                "balances", entry["balances"]
            )
    for uid, record in load_transactions(cfg).items():
        if not record.get("bank_country"):
            continue
        account_id = linked_account_id(
            record.get("bank_name"), record.get("iban"), record.get("currency"), uid
        )
        entry = accounts.setdefault(
            account_id,
            {
                "bank_key": f"{record['bank_name']}_{record['bank_country']}",
                "bank_name": record["bank_name"],
                "bank_country": record["bank_country"],
                "name": record.get("name", ""),
                "iban": record.get("iban", ""),
                "currency": record.get("currency", ""),
                "uids": set(),
                "balances": [],
            },
        )
        entry["uids"].add(uid)
    return accounts


def linked_transactions(cfg, account, date_from, date_to):
    """Stored transactions of every UID the account had, without duplicates"""
    stored = load_transactions(cfg)
    seen = set()
    transactions = []
    for uid in sorted(account["uids"]):
        for t in stored.get(uid, {}).get("transactions", []):
            day = transaction_date(t)
            if (date_from and day < date_from) or (date_to and day > date_to):
                continue
            key = t.get("entry_reference") or t.get("transaction_id") or json.dumps(
                t, sort_keys=True
            )
            if key not in seen:
                seen.add(key)
                transactions.append(t)
    transactions.sort(key=transaction_date, reverse=True)
    return transactions


def api_session(cfg, bank_key):
    accounts = linked_accounts(cfg)
    bank = next(
        (b for b in cfg["banks"] if f"{b['name']}_{b['country']}" == bank_key), None
    )
    if bank is None:
        raise ApiError(404, "Session not found", "NOT_FOUND")
    return {
        "session_id": bank_key,
        "aspsp": {"name": bank["name"], "country": bank["country"]},
        "accounts": [
            {
                "uid": account_id,
                "name": account["name"],
                "currency": account["currency"],
                "account_id": {"iban": account["iban"]},
                "account_servicer": {"name": account["bank_name"]},
            }
            for account_id, account in accounts.items()
            if account["bank_key"] == bank_key
        ],
    }


def handle_api(method, path, query, body, authorization):
    """Serve the subset of the Enable Banking API that Actual uses, from this exporter's data"""
    cfg = load_config()
    verify_api_token(cfg, authorization)
    parts = [p for p in path.split("/") if p]
    sessions = load_session()

    if method == "GET" and parts == ["application"]:
        return {"name": "enablebanking-prometheus-exporter", "kid": cfg["api"]["application_id"], "active": True}

    if method == "GET" and parts == ["aspsps"]:
        country = query.get("country", [None])[0]
        return {
            "aspsps": [
                {
                    "name": bank["name"],
                    "country": bank["country"],
                    "maximum_consent_validity": 180 * 24 * 3600,
                    "psu_types": ["personal"],
                    "beta": False,
                }
                for bank in cfg["banks"]
                if f"{bank['name']}_{bank['country']}" in sessions
                and (not country or bank["country"] == country)
            ]
        }

    if method == "POST" and parts == ["auth"]:
        aspsp = body.get("aspsp") or {}
        bank_key = f"{aspsp.get('name')}_{aspsp.get('country')}"
        if bank_key not in sessions:
            raise ApiError(422, f"Authorize {aspsp.get('name')} in the exporter first")
        code = uuid.uuid4().hex
        with state.lock:
            now = time.time()
            state.link_codes = {
                c: v for c, v in state.link_codes.items() if v["expires"] > now
            }
            state.link_codes[code] = {"bank_key": bank_key, "expires": now + 600}
        redirect_url = body.get("redirect_url", "")
        separator = "&" if "?" in redirect_url else "?"
        params = {"code": code, "state": body.get("state", "")}
        return {
            "url": f"{redirect_url}{separator}{urlencode(params)}",
            "authorization_id": code,
        }

    if method == "POST" and parts == ["sessions"]:
        with state.lock:
            link = state.link_codes.pop(body.get("code", ""), None)
        if not link or link["expires"] < time.time():
            raise ApiError(400, "Invalid or expired authorization code")
        return api_session(cfg, link["bank_key"])

    if method == "GET" and len(parts) == 2 and parts[0] == "sessions":
        return api_session(cfg, parts[1])

    if method == "GET" and len(parts) == 3 and parts[0] == "accounts":
        account = linked_accounts(cfg).get(parts[1])
        if account is None:
            raise ApiError(404, "Account not found", "NOT_FOUND")
        if parts[2] == "balances":
            return {"balances": account["balances"]}
        if parts[2] == "transactions":
            return {
                "transactions": linked_transactions(
                    cfg,
                    account,
                    query.get("date_from", [""])[0],
                    query.get("date_to", [""])[0],
                ),
                "continuation_key": None,
            }

    raise ApiError(404, "Not found", "NOT_FOUND")


class MetricsHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the metrics server"""

    def send_html(self, status, title, message, extra=""):
        """Send HTML response"""
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        html = f"<html><head><title>{title}</title></head><body><h1>{title}</h1><p>{message}</p>{extra}</body></html>"
        self.wfile.write(html.encode())

    def send_text(self, content_type, body):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        if self.path == "/":
            self.send_text("text/html; charset=utf-8", format_status())

        elif self.path == "/transactions":
            rows = transaction_rows(load_transactions(load_config()))
            self.send_text("application/json", json.dumps(rows, indent=2))

        elif self.path == "/transactions.csv":
            rows = transaction_rows(load_transactions(load_config()))
            self.send_text("text/csv; charset=utf-8", transactions_csv(rows))

        elif self.path == "/metrics":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.end_headers()
            self.wfile.write(format_metrics().encode())

        elif self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            status = "healthy" if not state.scrape_error else "unhealthy"
            self.wfile.write(status.encode())

        elif self.path == "/auth" or self.path.startswith("/auth?"):
            # Start OAuth flow - optionally with bank parameter
            try:
                cfg = load_config()

                # Parse bank index from query parameter
                bank_index = 0
                if "?" in self.path:
                    parsed_url = urlparse(self.path)
                    params = parse_qs(parsed_url.query)
                    if "bank" in params:
                        try:
                            bank_index = int(params["bank"][0])
                        except (ValueError, IndexError):
                            pass

                # Validate bank index
                if bank_index < 0 or bank_index >= len(cfg["banks"]):
                    bank_list = "<br>".join(
                        [
                            f"{i}: {b['name']} ({b['country']})"
                            for i, b in enumerate(cfg["banks"])
                        ]
                    )
                    self.send_html(
                        400,
                        "Invalid Bank",
                        f"Bank index {bank_index} is invalid. Available banks:<br>{bank_list}",
                    )
                    return

                bank = cfg["banks"][bank_index]
                jwt_token = create_jwt_token(cfg)
                base_headers = {"Authorization": f"Bearer {jwt_token}"}
                api_origin = cfg["api"]["origin"]

                # Get application details to get redirect URL
                r = requests.get(f"{api_origin}/application", headers=base_headers)
                if r.status_code != 200:
                    raise Exception(
                        f"Failed to get application details: {r.status_code} - {r.text}"
                    )

                app = r.json()

                # Generate state and store it
                auth_state = str(uuid.uuid4())
                state.pending_auth_state = auth_state
                state.pending_bank_index = bank_index

                # Create authorization request
                body = {
                    "access": {
                        "valid_until": (
                            datetime.now(timezone.utc) + timedelta(days=180)
                        ).isoformat()
                    },
                    "aspsp": {"name": bank["name"], "country": bank["country"]},
                    "state": auth_state,
                    "redirect_url": app["redirect_urls"][0],
                    "psu_type": "personal",
                }

                r = requests.post(f"{api_origin}/auth", json=body, headers=base_headers)
                if r.status_code != 200:
                    raise Exception(
                        f"Failed to create auth request: {r.status_code} - {r.text}"
                    )

                auth_url = r.json()["url"]

                # Redirect user to auth URL
                self.send_response(302)
                self.send_header("Location", auth_url)
                self.end_headers()
                logger.info(
                    f"Redirecting to auth URL for {bank['name']} ({bank['country']})"
                )

            except Exception as e:
                self.send_html(
                    500,
                    "Authentication Error",
                    f"Failed to start authentication: {str(e)}",
                )

        elif self.path.startswith("/auth/callback"):
            # Handle OAuth callback
            try:
                # Parse query parameters
                parsed_url = urlparse(self.path)
                params = parse_qs(parsed_url.query)

                if "code" not in params:
                    raise Exception("No authorization code received")

                # Verify state if we have one stored
                if "state" in params and state.pending_auth_state:
                    received_state = params["state"][0]
                    if received_state != state.pending_auth_state:
                        raise Exception("State mismatch - possible CSRF attack")

                auth_code = params["code"][0]

                # Create session with the auth code
                cfg = load_config()
                jwt_token = create_jwt_token(cfg)
                base_headers = {"Authorization": f"Bearer {jwt_token}"}
                api_origin = cfg["api"]["origin"]

                r = requests.post(
                    f"{api_origin}/sessions",
                    json={"code": auth_code},
                    headers=base_headers,
                )
                if r.status_code != 200:
                    raise Exception(
                        f"Failed to create session: {r.status_code} - {r.text}"
                    )

                session = r.json()

                # Get bank info from pending state or from session
                if state.pending_bank_index is not None:
                    bank = cfg["banks"][state.pending_bank_index]
                    bank_name = bank["name"]
                    bank_country = bank["country"]
                else:
                    bank_name = session.get("aspsp", {}).get("name", "unknown")
                    bank_country = session.get("aspsp", {}).get("country", "unknown")

                save_session(bank_name, bank_country, session)

                # Clear pending state
                state.pending_auth_state = None
                state.pending_bank_index = None

                # Trigger immediate scrape with new session
                threading.Thread(
                    target=scrape_balances, kwargs={"transactions": True}, daemon=True
                ).start()

                # Send success response
                account_count = len(session.get("accounts", []))
                self.send_html(
                    200,
                    "Authentication Successful!",
                    "Your session has been created and saved. The server will now scrape balances.",
                    '<p><a href="/metrics">View Metrics</a></p>',
                )
                logger.info(
                    f"Authentication successful! Session created with {account_count} account(s)"
                )

            except Exception as e:
                self.send_html(
                    500,
                    "Authentication Error",
                    f"Failed to complete authentication: {str(e)}",
                    '<p><a href="/auth">Try Again</a></p>',
                )

        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found\n")

    def log_message(self, format, *args):
        """Custom log format"""
        print(
            f"[{datetime.now().isoformat()}] {self.address_string()} - {format % args}"
        )


class ApiHandler(BaseHTTPRequestHandler):
    """Serves the Enable Banking API subset over TLS"""

    def respond(self, method):
        parsed = urlparse(self.path)
        try:
            body = {}
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                body = json.loads(self.rfile.read(length))
            status, payload = 200, handle_api(
                method,
                parsed.path,
                parse_qs(parsed.query),
                body,
                self.headers.get("Authorization"),
            )
        except ApiError as e:
            status, payload = e.status, e.payload
        except Exception as e:
            logger.error(f"API error on {method} {parsed.path}: {e}")
            status, payload = 500, {"code": 500, "message": "Internal error", "error": "INTERNAL"}
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())

    def do_GET(self):
        self.respond("GET")

    def do_POST(self):
        self.respond("POST")

    def log_message(self, format, *args):
        print(f"[{datetime.now().isoformat()}] api {self.address_string()} - {format % args}")


def main():
    cfg = load_config()
    port = int(os.environ.get("PORT", cfg["server"]["port"]))

    logger.info(f"EnableBanking Prometheus Exporter starting on port {port}")
    logger.info(f"Metrics endpoint: http://localhost:{port}/metrics")
    logger.info(f"Health endpoint: http://localhost:{port}/health")
    logger.info(f"Auth endpoint: http://localhost:{port}/auth")
    logger.info("Configured banks:")
    for i, bank in enumerate(cfg["banks"]):
        logger.info(
            f"  [{i}] {bank['name']} ({bank['country']}) - Auth at: http://localhost:{port}/auth?bank={i}"
        )
    logger.info(f"Scrape interval: {cfg['server']['scrape_interval_hours']} hours")

    # Start the scraping thread
    scraper_thread = threading.Thread(target=scrape_loop, daemon=True)
    scraper_thread.start()

    # Try initial scrape, but don't fail if no session exists yet
    logger.info("Attempting initial balance scrape...")
    try:
        scrape_balances()
    except Exception as e:
        logger.warning(
            f"Initial scrape failed (this is normal if not authenticated yet): {str(e)}"
        )
        logger.info(
            f"Visit http://localhost:{port}/auth to authenticate"
        )  # Start HTTP server
    api_server = cfg.get("api_server")
    if api_server:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(api_server["cert"], api_server["key"])
        api = ThreadingHTTPServer(("0.0.0.0", api_server["port"]), ApiHandler)
        api.socket = tls.wrap_socket(api.socket, server_side=True)
        threading.Thread(target=api.serve_forever, daemon=True).start()
        logger.info(f"Enable Banking API listening on 0.0.0.0:{api_server['port']}")

    server = HTTPServer(("0.0.0.0", port), MetricsHandler)
    logger.info(f"Server ready and listening on 0.0.0.0:{port}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down server...")
        server.shutdown()


if __name__ == "__main__":
    main()
