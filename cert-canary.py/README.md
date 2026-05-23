🔐 cert-canary

Continuous SSL/TLS certificate expiry monitor with multi-channel alerting.
Zero dependencies. Pure Python 3.8+. Cron-ready or daemon mode.

🟢 api.example.com:443       OK        87d left
🟡 staging.example.com:443  WARNING   24d left
🔴 legacy.example.com:8443  CRITICAL  4d left
💀 old.example.com:443      CRITICAL  EXPIRED 2d ago
⚫ internal.corp:443       ERROR     Connection refused

Features

Scans any number of hosts in parallel via ThreadPoolExecutor
Grades each cert: OK / INFO / WARNING / CRITICAL
Alerts via Slack, Discord, PagerDuty, Email, or any generic webhook
Cron-ready one-shot or persistent daemon loop
Exit codes 0/1/2 for Nagios, PagerDuty, and CI pipelines
Quick start

git clone https://github.com/yourname/cert-canary.git
cd cert-canary
python3 main.py --host example.com --once
Alert channels

Channel	Config key	Env var
Slack	slack_webhook	CANARY_SLACK_WEBHOOK
Discord	discord_webhook	CANARY_DISCORD_WEBHOOK
PagerDuty	pagerduty_key	CANARY_PAGERDUTY_KEY
Email	smtp	—
Webhook	webhook_url	CANARY_WEBHOOK_URL