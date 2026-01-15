# ONS API Tools

ONS CDN 플랫폼 API를 활용한 CLI 도구 모음입니다.

## Tools

| Tool | Description | Path |
|------|-------------|------|
| SSL API Manager | SSL 인증서 관리 CLI | [ssl/](./ssl/) |

## Requirements

- Python 3.10+
- requests

```bash
pip install requests
```

## Quick Start

### SSL Certificate Management

```bash
# Deploy new certificate to staging
python ssl/ssl_api_manager.py staging-deploy \
    --id <USER_ID> \
    --api-key <API_KEY> \
    --ssl-cert cert.pem \
    --ssl-key key.pem \
    --domain-list "example.com"

# Check deployment history
python ssl/ssl_api_manager.py history \
    --id <USER_ID> \
    --api-key <API_KEY> \
    --ssl-file-name example.com

# Finalize deployment
python ssl/ssl_api_manager.py deploy \
    --id <USER_ID> \
    --api-key <API_KEY> \
    --ssl-file-name example.com
```

## License

MIT License
