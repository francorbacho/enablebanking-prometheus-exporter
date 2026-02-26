# EnableBanking Prometheus Exporter

A Prometheus-compatible HTTP metrics server that scrapes bank account balances using the EnableBanking API.

## Getting Started

1. Sign up in https://enablebanking.com/cp/applications
2. Get your application ID and `*.pem` certificate
3. Configure your instance (`config.yml`) and start the dockerfile
4. Visit `http://localhost:8080/auth?bank=N` (where N is the bank index)
5. Complete the OAuth flow in your browser

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

- **session_file**: Where to store authentication session

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
