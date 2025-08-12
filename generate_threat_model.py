#!/usr/bin/env python3
import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Any, Tuple


def load_model(model_path: str) -> Dict[str, Any]:
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model file not found: {model_path}")
    with open(model_path, "r", encoding="utf-8") as f:
        return json.load(f)


def ensure_out_dir(out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)


def group_assets_by_boundary(assets: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    boundaries: Dict[str, List[Dict[str, Any]]] = {}
    for asset in assets:
        boundary = asset.get("boundary", "Unspecified")
        boundaries.setdefault(boundary, []).append(asset)
    return boundaries


def sanitize_id(value: str) -> str:
    return "_" + "".join(ch if ch.isalnum() else "_" for ch in value)


def build_mermaid(model: Dict[str, Any]) -> str:
    assets: List[Dict[str, Any]] = model.get("assets", [])
    flows: List[Dict[str, Any]] = model.get("flows", [])

    id_map: Dict[str, str] = {}
    for asset in assets:
        asset_id = asset.get("id")
        label = asset.get("name", asset_id)
        mid = sanitize_id(asset_id)
        id_map[asset_id] = mid

    lines: List[str] = []
    lines.append("flowchart LR")
    lines.append("  %% Trust boundaries as subgraphs")

    boundaries = group_assets_by_boundary(assets)
    for boundary_name, boundary_assets in boundaries.items():
        lines.append(f"  subgraph {sanitize_id(boundary_name)}[{boundary_name}]")
        for asset in boundary_assets:
            aid = id_map[asset["id"]]
            label = f"{asset.get('name', asset['id'])}\\n({asset.get('type', 'asset')})"
            shape = asset.get("shape", "rect")
            if shape == "circle":
                lines.append(f"    {aid}(({label}))")
            elif shape == "stadium":
                lines.append(f"    {aid}([{label}])")
            elif shape == "subroutine":
                lines.append(f"    {aid}[[{label}]])")
            else:
                lines.append(f"    {aid}[{label}]")
        lines.append("  end")

    lines.append("  %% Data flows")
    for flow in flows:
        src = id_map.get(flow["from"])  # type: ignore[index]
        dst = id_map.get(flow["to"])  # type: ignore[index]
        if not src or not dst:
            # skip flows with unresolved assets
            continue
        label = flow.get("protocol", flow.get("label", "flow"))
        lines.append(f"  {src} -- \"{label}\" --> {dst}")

    # Styling boundaries lightly
    boundary_colors = ["#f2f7ff", "#f7fff2", "#fff7f2", "#f2fff7"]
    for idx, boundary_name in enumerate(boundaries.keys()):
        color = boundary_colors[idx % len(boundary_colors)]
        lines.append(f"  style {sanitize_id(boundary_name)} fill:{color},stroke:#999,stroke-width:1px")

    return "\n".join(lines)


Threat = Dict[str, Any]


def build_threat_catalog() -> Dict[str, Dict[str, Any]]:
    # Catalog defines base threats and mitigations
    return {
        "device_firmware_vuln": {
            "category": "Device-Level",
            "title": "Firmware vulnerabilities",
            "description": "Unsigned or vulnerable firmware enables persistence and device takeover.",
            "mitigations": [
                "Secure Boot with verified boot chain",
                "Signed firmware and strict versioning",
                "Secure OTA updates with rollback protection",
                "Regular vulnerability scanning and SBOM management",
            ],
            "applies_to_types": ["device", "sensor", "actuator"],
        },
        "device_physical_tamper": {
            "category": "Device-Level",
            "title": "Physical tampering",
            "description": "Adversaries can access debug ports, extract secrets, or alter hardware.",
            "mitigations": [
                "Tamper-evident and tamper-resistant enclosures",
                "Disable/lock debug interfaces in production",
                "Secure elements/TPM for key storage",
                "Tamper sensors with alerting and zeroization",
            ],
            "applies_to_types": ["device", "gateway"],
        },
        "comm_eavesdropping": {
            "category": "Communication",
            "title": "Eavesdropping",
            "description": "Unencrypted or poorly configured links expose data in transit.",
            "mitigations": [
                "TLS 1.2+ with modern ciphers",
                "Mutual TLS for device authentication",
                "WPA3 or cellular with SIM-based auth",
                "Rotate keys; avoid static shared secrets",
            ],
            "applies_to_flows": True,
        },
        "comm_mitm": {
            "category": "Communication",
            "title": "Man-in-the-middle",
            "description": "Traffic interception or impersonation between nodes.",
            "mitigations": [
                "Certificate pinning and strict hostname verification",
                "Mutual TLS and hardware-backed keys",
                "Use message authentication (HMAC/MAC) for app-layer integrity",
                "Replay protection (nonces, timestamps)",
            ],
            "applies_to_flows": True,
        },
        "data_privacy": {
            "category": "Data",
            "title": "Privacy breaches",
            "description": "Sensitive data exposure or over-collection enabling re-identification.",
            "mitigations": [
                "Data minimization and purpose limitation",
                "Field-level encryption and tokenization",
                "Access controls with least privilege",
                "Anonymization/pseudonymization where possible",
            ],
            "applies_to_types": ["datastore", "cloud_service", "gateway"],
            "applies_to_flows": True,
        },
        "data_integrity": {
            "category": "Data",
            "title": "Data integrity compromise",
            "description": "Unauthorized or undetected modification of data in transit or at rest.",
            "mitigations": [
                "Cryptographic integrity (HMAC, signatures)",
                "Immutable/append-only logs and versioned storage",
                "Checksums and validation on ingestion",
                "Strong change control and auditing",
            ],
            "applies_to_types": ["datastore", "cloud_service", "gateway"],
            "applies_to_flows": True,
        },
        "platform_cloud_vuln": {
            "category": "Platform",
            "title": "Cloud infrastructure vulnerabilities",
            "description": "Misconfiguration or unpatched components enabling privilege escalation or breach.",
            "mitigations": [
                "Least-privilege IAM and role isolation",
                "Network segmentation and private endpoints",
                "Continuous patching and managed services",
                "CSPM, SIEM, and runtime monitoring",
            ],
            "applies_to_types": ["cloud_service", "datastore", "portal"],
        },
    }


def build_threat_instances(model: Dict[str, Any]) -> List[Threat]:
    catalog = build_threat_catalog()
    assets: List[Dict[str, Any]] = model.get("assets", [])
    flows: List[Dict[str, Any]] = model.get("flows", [])

    threats: List[Threat] = []

    # Asset-based threats
    for asset in assets:
        asset_type = asset.get("type", "asset")
        for threat_id, spec in catalog.items():
            if spec.get("applies_to_types") and asset_type in spec["applies_to_types"]:
                threats.append({
                    "threat_id": threat_id,
                    "category": spec["category"],
                    "title": spec["title"],
                    "description": spec["description"],
                    "mitigations": spec["mitigations"],
                    "target_type": "asset",
                    "target_id": asset["id"],
                    "target_name": asset.get("name", asset["id"]),
                })

    # Flow-based threats
    for flow in flows:
        for threat_id, spec in catalog.items():
            if spec.get("applies_to_flows"):
                threats.append({
                    "threat_id": threat_id,
                    "category": spec["category"],
                    "title": spec["title"],
                    "description": spec["description"],
                    "mitigations": spec["mitigations"],
                    "target_type": "flow",
                    "target_id": f"{flow['from']}->{flow['to']}",
                    "target_name": flow.get("label", flow.get("protocol", "data flow")),
                })

    return threats


def write_markdown(out_path: str, model: Dict[str, Any], mermaid_diagram: str, threats: List[Threat]) -> None:
    title = model.get("title", "IoT Threat Model")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(f"## {title}\n\n")
        f.write(f"Generated: {datetime.utcnow().isoformat()}Z\n\n")
        f.write("**Diagram**\n\n")
        f.write("```mermaid\n")
        f.write(mermaid_diagram)
        f.write("\n````\n\n".replace("````", "```"))

        f.write("**Threats by category**\n\n")
        # Group threats
        by_cat: Dict[str, List[Threat]] = {}
        for t in threats:
            by_cat.setdefault(t["category"], []).append(t)
        for category, items in by_cat.items():
            f.write(f"### {category}\n\n")
            for t in items:
                target_label = f"asset: {t['target_name']}" if t["target_type"] == "asset" else f"flow: {t['target_name']}"
                f.write(f"- **{t['title']}** ({target_label}) — {t['description']}\n")
                f.write("  - Mitigations:\n")
                for m in t["mitigations"]:
                    f.write(f"    - {m}\n")
            f.write("\n")


def write_html(out_path: str, model: Dict[str, Any], mermaid_diagram: str, threats: List[Threat]) -> None:
    title = model.get("title", "IoT Threat Model")
    # Minimal self-contained HTML with mermaid rendering
    html = f"""
<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"UTF-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />
  <title>{title}</title>
  <script src=\"https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js\"></script>
  <style>
    body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; margin: 24px; }}
    h1, h2, h3 {{ margin: 16px 0 8px; }}
    .diagram {{ border: 1px solid #e0e0e0; border-radius: 8px; padding: 8px; background: #fff; }}
    .threats {{ margin-top: 24px; }}
    .chip {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 12px; margin-right: 6px; color: #fff; }}
    .Device-Level {{ background: #1f77b4; }}
    .Communication {{ background: #2ca02c; }}
    .Data {{ background: #ff7f0e; }}
    .Platform {{ background: #9467bd; }}
    .mitigations {{ margin: 4px 0 12px 0; }}
  </style>
</head>
<body>
  <h2>{title}</h2>
  <div>Generated: {datetime.utcnow().isoformat()}Z</div>

  <div class=\"diagram\">
    <pre class=\"mermaid\">{mermaid_diagram}</pre>
  </div>

  <div class=\"threats\">
    <h3>Threats by category</h3>
    {build_html_threats(threats)}
  </div>

  <script>mermaid.initialize({{ startOnLoad: true, securityLevel: 'loose' }});</script>
</body>
</html>
"""
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)


def build_html_threats(threats: List[Threat]) -> str:
    # Group by category
    by_cat: Dict[str, List[Threat]] = {}
    for t in threats:
        by_cat.setdefault(t["category"], []).append(t)
    parts: List[str] = []
    for category, items in by_cat.items():
        parts.append(f"<h4><span class='chip {category}'>{category}</span></h4>")
        for t in items:
            target_label = (
                f"asset: {t['target_name']}" if t["target_type"] == "asset" else f"flow: {t['target_name']}"
            )
            parts.append(f"<div><strong>{t['title']}</strong> <em>({target_label})</em><br/>{t['description']}</div>")
            parts.append("<div class='mitigations'><em>Mitigations:</em><ul>" + "".join(
                f"<li>{m}</li>" for m in t["mitigations"]
            ) + "</ul></div>")
    return "\n".join(parts)


def write_csv(out_path: str, threats: List[Threat]) -> None:
    import csv
    headers = [
        "threat_id",
        "category",
        "title",
        "target_type",
        "target_id",
        "target_name",
        "description",
        "mitigations",
    ]
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for t in threats:
            writer.writerow([
                t.get("threat_id"),
                t.get("category"),
                t.get("title"),
                t.get("target_type"),
                t.get("target_id"),
                t.get("target_name"),
                t.get("description"),
                " | ".join(t.get("mitigations", [])),
            ])


def write_json(out_path: str, model: Dict[str, Any], threats: List[Threat], mermaid_diagram: str) -> None:
    payload = {
        "model": model,
        "threats": threats,
        "diagram": {
            "format": "mermaid",
            "content": mermaid_diagram,
        },
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


SAMPLE_MODEL: Dict[str, Any] = {
    "title": "IoT Threat Model (Sample)",
    "boundaries": ["Field / Device", "Edge / Gateway", "Cloud / Platform"],
    "assets": [
        {"id": "device01", "name": "Field Device", "type": "device", "boundary": "Field / Device", "shape": "stadium"},
        {"id": "gateway01", "name": "IoT Gateway", "type": "gateway", "boundary": "Edge / Gateway"},
        {"id": "ingest01", "name": "Ingestion Service", "type": "cloud_service", "boundary": "Cloud / Platform"},
        {"id": "iot_hub01", "name": "IoT Hub", "type": "cloud_service", "boundary": "Cloud / Platform"},
        {"id": "datalake01", "name": "Data Lake", "type": "datastore", "boundary": "Cloud / Platform"},
        {"id": "portal01", "name": "Admin Portal", "type": "portal", "boundary": "Cloud / Platform", "shape": "stadium"},
    ],
    "flows": [
        {"from": "device01", "to": "gateway01", "protocol": "MQTT over TLS", "label": "Telemetry"},
        {"from": "gateway01", "to": "ingest01", "protocol": "HTTPS", "label": "Ingest API"},
        {"from": "ingest01", "to": "datalake01", "protocol": "Private Link", "label": "Store"},
        {"from": "iot_hub01", "to": "datalake01", "protocol": "Event Routing", "label": "Events"},
        {"from": "portal01", "to": "ingest01", "protocol": "HTTPS", "label": "Management"},
    ],
}


def save_sample_model(path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(SAMPLE_MODEL, f, indent=2)


def main(argv: List[str]) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Generate IoT threat model artifacts from a JSON model.")
    parser.add_argument("--model", default="/workspace/model.json", help="Path to model JSON file")
    parser.add_argument("--out", default="/workspace/out", help="Output directory")
    parser.add_argument("--write-sample", action="store_true", help="Write a sample model.json and exit")
    args = parser.parse_args(argv)

    if args.write_sample:
        save_sample_model(args.model)
        print(f"Sample model written to {args.model}")
        return 0

    model = load_model(args.model)
    ensure_out_dir(args.out)

    mermaid_diagram = build_mermaid(model)
    threats = build_threat_instances(model)

    md_path = os.path.join(args.out, "threat_model.md")
    html_path = os.path.join(args.out, "threat_model.html")
    csv_path = os.path.join(args.out, "threats.csv")
    json_path = os.path.join(args.out, "threat_model.json")

    write_markdown(md_path, model, mermaid_diagram, threats)
    write_html(html_path, model, mermaid_diagram, threats)
    write_csv(csv_path, threats)
    write_json(json_path, model, threats, mermaid_diagram)

    print(f"Generated: {md_path}\n{html_path}\n{csv_path}\n{json_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))