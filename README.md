### IoT Threat Modeling Tool (Business-Oriented)

This tool generates a business-friendly, dynamic IoT threat model from a simple JSON description. It produces:

- Mermaid diagram illustrating trust boundaries and data flows
- HTML report (rendered diagram + categorized threats + mitigations)
- Markdown report
- CSV export of threats
- JSON export of the computed model

It focuses on four primary categories aligned with the prompt and inspired by Microsoft Threat Modeling Tool (MTMT) data-flow-centric modeling:

- Device-Level Threats: Firmware vulnerabilities, physical tampering
- Communication Threats: Eavesdropping, man-in-the-middle
- Data Threats: Privacy breaches, integrity compromise
- Platform Threats: Cloud infrastructure vulnerabilities

The diagram uses boundary subgraphs (akin to trust boundaries in MTMT) and nodes/flows that mirror DFD elements.

### Quick start

1. Ensure Python 3.8+ is available.
2. Use the provided sample model or write your own.

```bash
python3 /workspace/generate_threat_model.py --model /workspace/model.json --out /workspace/out
```

Artifacts will be written to `/workspace/out`:
- `threat_model.html` (open in a browser to see the rendered diagram)
- `threat_model.md`
- `threat_model.json`
- `threats.csv`

To write a fresh sample model file:
```bash
python3 /workspace/generate_threat_model.py --write-sample --model /workspace/model.json
```

### Model JSON schema

```json
{
  "title": "IoT Threat Model (Sample)",
  "boundaries": ["Field / Device", "Edge / Gateway", "Cloud / Platform"],
  "assets": [
    {"id": "device01", "name": "Field Device", "type": "device", "boundary": "Field / Device", "shape": "stadium"}
    // more assets...
  ],
  "flows": [
    {"from": "device01", "to": "gateway01", "protocol": "MQTT over TLS", "label": "Telemetry"}
    // more flows...
  ]
}
```

- `boundaries` become subgraphs to visually represent trust boundaries.
- `assets.type` influences which threats are generated.
- `flows` automatically receive communication and data threats.

### MTMT alignment

- Treat each `asset` as a DFD element.
- Treat each `flow` as a DFD data flow.
- Subgraphs approximate trust boundaries.
- The generated threats mirror an MTMT-style catalog for the four categories with curated mitigations.

You can recreate this in MTMT by creating equivalent elements/boundaries and copying the diagram/flows. The `threats.csv` provides a quick importable reference for tracking mitigations.
