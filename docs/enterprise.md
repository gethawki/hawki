# Hawk-i Enterprise

Hawk-i is 100% open source under the MIT License. Every feature is free and runs locally. This document covers self-hosting and the paid services that are sold separately from the software.

## The Model: Free Software, Paid Services

You never buy a license. The software is free forever. Revenue comes from **services** (consulting, support, training, and custom audits), not from the code. This mirrors how Linux, PostgreSQL, and Kubernetes built sustainable open source ecosystems: the tool is a public good, and expertise around it is the product.

- **No vendor lock-in** - you own your stack.
- **No paywalled features** - the Deep Agent, PoC generation, Immunefi reports, contract registry, and doctor checks are all free and local.
- **Security is a public good** - everyone benefits from better tooling.

## Self-Hosting

### Docker

Build and run the scanner in a container:

```bash
docker build -t hawki -f docker/Dockerfile .
docker run --rm --user $(id -u):$(id -g) -v $(pwd)/contracts:/work -w /work hawki scan . --format html
```

### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'
services:
  hawki:
    build: .
    command: hawki scan /repo --format html
    volumes:
      - ./contracts:/repo
      - hawki_reports:/hawki_reports
    environment:
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - ETH_RPC_URL=${ETH_RPC_URL}
volumes:
  hawki_reports:
```

The canonical published image is `levichinecherem/hawki`. Pull it directly instead of building if you prefer:

```bash
docker pull levichinecherem/hawki:latest
docker run --rm --user $(id -u):$(id -g) -v $(pwd):/work -w /work levichinecherem/hawki scan . --format html
```

### Air-Gapped Environments

Hawk-i runs entirely offline except for three optional network calls:

- LLM API calls (only when `--ai` or the Deep Agent is used, and only to the provider you choose)
- RPC calls to blockchain nodes (only for deployed-contract scanning, verification, and monitoring)
- Block explorer API calls (only when fetching verified source)

All three are optional. A pure static scan of local source needs no network access at all.

## Paid Services

For organisations that want more than the open source tool, the following are offered as separate paid engagements:

- **Priority support** with agreed response times
- **On-prem deployment help** - Kubernetes, CI/CD integration, and secret management
- **Custom rule development** tailored to your protocol
- **Team training** on Hawk-i and smart-contract security workflows
- **Custom audits** performed by the maintainers

## Roadmap Items (Not Yet Shipped)

The following are planned and are called out here so the documentation does not imply they already exist:

- Production-ready Helm charts for Kubernetes with horizontal scaling of scan workers, persistent storage for reports and memory, and Prometheus/Grafana integration.
- Compliance packages (SOC2, GDPR, audit trails).

## Contact

Enterprise and services enquiries, along with bug reports and questions, go through the project's public channels:

- **GitHub Issues:** https://github.com/gethawki/hawki/issues
- **GitHub Discussions:** https://github.com/gethawki/hawki/discussions
