# Contributing to AI Hunter

We welcome community feedback, domain classifications, and code contributions!

## How You Can Contribute

1. **False Positive & Whitelist Submissions:** Open an issue if high-entropy CDNs or trusted services are flagged incorrectly.
2. **New Heuristics:** Propose new DNS tunneling or DGA detection algorithms.
3. **Automated PR Generator:** Comment `/auto-fix` or `/implement` on approved issues to trigger our automated bot to generate branch patches and PRs.

## Development & Testing

```bash
git clone https://github.com/your-username/ai-hunter.git
cd ai-hunter
pip install -r requirements.txt -r requirements-dev.txt
pytest tests -v
```
