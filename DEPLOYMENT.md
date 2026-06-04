# CyberScan Deployment

CyberScan can run on Python web hosts that provide a public `PORT` environment variable.

## Start command

```bash
python app.py --host 0.0.0.0 --port $PORT
```

The included `Procfile` already uses this command.

## Required environment variables

Set a stronger owner password before deploying:

```text
CYBERSCAN_OWNER_PASSWORD=change-this-local-prototype-password
```

Optional trusted origins for your domain:

```text
CYBERSCAN_TRUSTED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
```

Optional real email OTP delivery:

```text
CYBERSCAN_SMTP_HOST=smtp.gmail.com
CYBERSCAN_SMTP_PORT=587
CYBERSCAN_SMTP_USERNAME=your_email@gmail.com
CYBERSCAN_SMTP_PASSWORD=your_app_password
CYBERSCAN_SMTP_FROM=your_email@gmail.com
```

Without SMTP settings, CyberScan uses a temporary local OTP for prototype sign-in.

## Domain setup

After the app is deployed, add your custom domain in the hosting dashboard and point your domain DNS to the value provided by the host.
