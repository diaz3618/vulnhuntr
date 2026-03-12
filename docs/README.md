# Vulnhuntr Documentation

This directory contains technical documentation, and academic project materials for the Vulnhuntr fork.

---

## Structure

### Architecture

Split into `architecture/` for easier navigation:

- [architecture/README.md](architecture/README.md) — Overview, component table, design decisions
- [architecture/components.md](architecture/components.md) — Detailed component implementations
- [architecture/analysis-pipeline.md](architecture/analysis-pipeline.md) — Data flow and iterative analysis algorithm
- [architecture/data-models.md](architecture/data-models.md) — Pydantic models and data types
- [architecture/configuration.md](architecture/configuration.md) — Environment variables, CLI args, logging
- [architecture/diagrams.md](architecture/diagrams.md) — Mermaid flowcharts for the major subsystems

### MCP Integration

Split into `mcp-setup/`:

- [mcp-setup/README.md](mcp-setup/README.md) — Quick start, file layout, troubleshooting
- [mcp-setup/configuration.md](mcp-setup/configuration.md) — Transport types, config reference, API reference
- [mcp-setup/analysis-integration.md](mcp-setup/analysis-integration.md) — Analysis integration settings and examples

### Models

- [models/anthropic-models.md](models/anthropic-models.md) - Current Anthropic Claude model IDs and config variables
- [models/openai-models.md](models/openai-models.md) - Current OpenAI text model IDs, aliases, and compatibility notes
- [models/openrouter-free-models.md](models/openrouter-free-models.md) — OpenRouter free model list and config variables

### Troubleshooting

- [troubleshooting.md](troubleshooting.md) — Common issues and fixes

### Project Documentation (Academic)

Located in `project/`:

- [project/TECHNICAL_DOCUMENTATION.md](project/TECHNICAL_DOCUMENTATION.md) — Codebase walkthrough and usage guide
- [project/ARCHITECTURE_REFACTOR.md](project/ARCHITECTURE_REFACTOR.md) — Planned modular refactor
- [project/AREAS_OF_IMPROVEMENT.md](project/AREAS_OF_IMPROVEMENT.md) — Categorized improvement backlog
- [project/PROJECT_PROPOSAL.md](project/PROJECT_PROPOSAL.md) — CS5374 course project proposal
- [project/RESEARCH_METHODOLOGY.md](project/RESEARCH_METHODOLOGY.md) — Research questions and experimental design
- [project/LITERATURE_REVIEW.md](project/LITERATURE_REVIEW.md) — Related work and background
- [project/MCP_SERVERS_RESEARCH.md](project/MCP_SERVERS_RESEARCH.md) — MCP server research and integration targets
