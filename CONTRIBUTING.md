# Contributing to AI Hunter

We welcome contributions, bug fixes, and whitelist recommendations from the community!

## How to Contribute

1. **Reporting False Positives:** Open an issue with the domain and service details so other users can reference it.
2. **Pull Requests:** Fork the repository, create a branch, write unit tests, and submit a PR.
3. **Manual Verification:** To maintain zero-trust security for homelab users, all PRs are reviewed manually and tested against the test suite.

## Development & Testing

```bash
git clone https://github.com/your-username/ai-hunter.git
cd ai-hunter
pip install -r requirements.txt -r requirements-dev.txt
pytest tests -v
```
