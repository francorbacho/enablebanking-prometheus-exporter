# EnableBanking Prometheus Exporter

A Prometheus-compatible HTTP metrics server that scrapes bank account balances using the EnableBanking API.

## Getting Started

1. Sign up in https://enablebanking.com/cp/applications
2. Get your application ID and `*.pem` certificate
3. Configure your instance (`config.yml`) and start the dockerfile
4. Visit `http://localhost:8080/auth?bank=N` (where N is the bank index)
5. Complete the OAuth flow in your browser. The exporter requests up to 180 days of consent; a bank may grant less. Reauthorize when consent expires. The balance scrape interval does not renew consent.

## Configuration

All settings are in `config.yml`:

- **api**: EnableBanking API credentials
  - `origin`: API endpoint (usually `https://api.enablebanking.com`)
  - `application_id`: Your EnableBanking application ID
  - `key_path`: Path to your private key `.pem` file

- **banks**: Array of bank providers to support
  - `name`: Bank name (e.g., "Revolut", "Santander")
  - `country`: ISO country code (e.g., "ES", "GB", "FR")

- **server**: Server settings
  - `port`: HTTP port (default: 8080)
  - `scrape_interval_hours`: How often to scrape balances
  - `transactions_interval_hours`: How often to fetch transactions (default: 6)
  - `transactions_days`: How many days of history to fetch for a new account (default: 90)

- **session_file**: Where to store authentication session
- **transactions_file**: Where to store transactions (default: `transactions.json` next to `session_file`)

## Endpoints

- `/`: Configured banks, their consent status and accounts
- `/metrics`: Balances in Prometheus format
- `/transactions`, `/transactions.csv`: Stored transactions, newest first. Amounts are negative for money going out.

## Prometheus Configuration

Add this to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'enablebanking-exporter'
    scrape_interval: 2h
    static_configs:
      - targets: ['enablebanking-prometheus-exporter:8080']  # Use service name in docker-compose
        # Or for local: - targets: ['localhost:8080']
```

## Resources

- https://github.com/enablebanking/enablebanking-api-samples

## License

This project is provided as-is for personal use.
