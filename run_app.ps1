$ErrorActionPreference = "Stop"

Set-Location -LiteralPath $PSScriptRoot

if (-not $env:CYBERSCAN_MONGO_URI) {
    $env:CYBERSCAN_MONGO_URI = "mongodb://localhost:27017/cyberscan"
}

if (-not $env:CYBERSCAN_MONGO_DB) {
    $env:CYBERSCAN_MONGO_DB = "cyberscan"
}

python app.py --host 127.0.0.1 --port 8006
