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

Optional Gmail OTP and forgot-password delivery:

```text
CYBERSCAN_SMTP_HOST=smtp.gmail.com
CYBERSCAN_SMTP_PORT=587
CYBERSCAN_SMTP_USERNAME=your_email@gmail.com
CYBERSCAN_SMTP_PASSWORD=your_app_password
CYBERSCAN_SMTP_FROM=your_email@gmail.com
```

Use a Gmail App Password, not your normal Gmail password. In Google Account settings, enable 2-Step Verification, create an App Password for Mail, and use that value as `CYBERSCAN_SMTP_PASSWORD`.

Without SMTP settings, CyberScan shows a temporary local OTP/reset code for capstone demonstration. For real deployment, configure Gmail SMTP so verification and forgot-password codes are emailed to the owner.

CyberScan does not pre-fill or remember the owner password in the login page. Reset passwords are stored only as a local SHA-256 hash in `data/security.json`.

## Optional MongoDB storage

CyberScan can run with local JSON/file storage only, or it can mirror important records to MongoDB for a more commercial deployment style.

Install dependencies:

```bash
pip install -r requirements.txt
```

Local MongoDB:

```text
CYBERSCAN_MONGO_URI=mongodb://localhost:27017
CYBERSCAN_MONGO_DB=cyberscan
```

MongoDB Atlas:

```text
CYBERSCAN_MONGO_URI=mongodb+srv://USERNAME:PASSWORD@cluster.mongodb.net/?retryWrites=true&w=majority
CYBERSCAN_MONGO_DB=cyberscan
```

When MongoDB is configured, CyberScan uses these collections:

```text
app_state
scans
audit_logs
```

The system still keeps local file storage as a fallback, so it can run even if MongoDB is not configured.

## Domain setup

After the app is deployed, add your custom domain in the hosting dashboard and point your domain DNS to the value provided by the host.
