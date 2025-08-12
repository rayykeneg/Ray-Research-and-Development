## IoT Threat Model (Sample)

Generated: 2025-08-12T22:35:35.242214Z

**Diagram**

```mermaid
flowchart LR
  %% Trust boundaries as subgraphs
  subgraph _Field___Device[Field / Device]
    _device01([Field Device\n(device)])
  end
  subgraph _Edge___Gateway[Edge / Gateway]
    _gateway01[IoT Gateway\n(gateway)]
  end
  subgraph _Cloud___Platform[Cloud / Platform]
    _ingest01[Ingestion Service\n(cloud_service)]
    _iot_hub01[IoT Hub\n(cloud_service)]
    _datalake01[Data Lake\n(datastore)]
    _portal01([Admin Portal\n(portal)])
  end
  %% Data flows
  _device01 -- "MQTT over TLS" --> _gateway01
  _gateway01 -- "HTTPS" --> _ingest01
  _ingest01 -- "Private Link" --> _datalake01
  _iot_hub01 -- "Event Routing" --> _datalake01
  _portal01 -- "HTTPS" --> _ingest01
  style _Field___Device fill:#f2f7ff,stroke:#999,stroke-width:1px
  style _Edge___Gateway fill:#f7fff2,stroke:#999,stroke-width:1px
  style _Cloud___Platform fill:#fff7f2,stroke:#999,stroke-width:1px
```

**Threats by category**

### Device-Level

- **Firmware vulnerabilities** (asset: Field Device) — Unsigned or vulnerable firmware enables persistence and device takeover.
  - Mitigations:
    - Secure Boot with verified boot chain
    - Signed firmware and strict versioning
    - Secure OTA updates with rollback protection
    - Regular vulnerability scanning and SBOM management
- **Physical tampering** (asset: Field Device) — Adversaries can access debug ports, extract secrets, or alter hardware.
  - Mitigations:
    - Tamper-evident and tamper-resistant enclosures
    - Disable/lock debug interfaces in production
    - Secure elements/TPM for key storage
    - Tamper sensors with alerting and zeroization
- **Physical tampering** (asset: IoT Gateway) — Adversaries can access debug ports, extract secrets, or alter hardware.
  - Mitigations:
    - Tamper-evident and tamper-resistant enclosures
    - Disable/lock debug interfaces in production
    - Secure elements/TPM for key storage
    - Tamper sensors with alerting and zeroization

### Data

- **Privacy breaches** (asset: IoT Gateway) — Sensitive data exposure or over-collection enabling re-identification.
  - Mitigations:
    - Data minimization and purpose limitation
    - Field-level encryption and tokenization
    - Access controls with least privilege
    - Anonymization/pseudonymization where possible
- **Data integrity compromise** (asset: IoT Gateway) — Unauthorized or undetected modification of data in transit or at rest.
  - Mitigations:
    - Cryptographic integrity (HMAC, signatures)
    - Immutable/append-only logs and versioned storage
    - Checksums and validation on ingestion
    - Strong change control and auditing
- **Privacy breaches** (asset: Ingestion Service) — Sensitive data exposure or over-collection enabling re-identification.
  - Mitigations:
    - Data minimization and purpose limitation
    - Field-level encryption and tokenization
    - Access controls with least privilege
    - Anonymization/pseudonymization where possible
- **Data integrity compromise** (asset: Ingestion Service) — Unauthorized or undetected modification of data in transit or at rest.
  - Mitigations:
    - Cryptographic integrity (HMAC, signatures)
    - Immutable/append-only logs and versioned storage
    - Checksums and validation on ingestion
    - Strong change control and auditing
- **Privacy breaches** (asset: IoT Hub) — Sensitive data exposure or over-collection enabling re-identification.
  - Mitigations:
    - Data minimization and purpose limitation
    - Field-level encryption and tokenization
    - Access controls with least privilege
    - Anonymization/pseudonymization where possible
- **Data integrity compromise** (asset: IoT Hub) — Unauthorized or undetected modification of data in transit or at rest.
  - Mitigations:
    - Cryptographic integrity (HMAC, signatures)
    - Immutable/append-only logs and versioned storage
    - Checksums and validation on ingestion
    - Strong change control and auditing
- **Privacy breaches** (asset: Data Lake) — Sensitive data exposure or over-collection enabling re-identification.
  - Mitigations:
    - Data minimization and purpose limitation
    - Field-level encryption and tokenization
    - Access controls with least privilege
    - Anonymization/pseudonymization where possible
- **Data integrity compromise** (asset: Data Lake) — Unauthorized or undetected modification of data in transit or at rest.
  - Mitigations:
    - Cryptographic integrity (HMAC, signatures)
    - Immutable/append-only logs and versioned storage
    - Checksums and validation on ingestion
    - Strong change control and auditing
- **Privacy breaches** (flow: Telemetry) — Sensitive data exposure or over-collection enabling re-identification.
  - Mitigations:
    - Data minimization and purpose limitation
    - Field-level encryption and tokenization
    - Access controls with least privilege
    - Anonymization/pseudonymization where possible
- **Data integrity compromise** (flow: Telemetry) — Unauthorized or undetected modification of data in transit or at rest.
  - Mitigations:
    - Cryptographic integrity (HMAC, signatures)
    - Immutable/append-only logs and versioned storage
    - Checksums and validation on ingestion
    - Strong change control and auditing
- **Privacy breaches** (flow: Ingest API) — Sensitive data exposure or over-collection enabling re-identification.
  - Mitigations:
    - Data minimization and purpose limitation
    - Field-level encryption and tokenization
    - Access controls with least privilege
    - Anonymization/pseudonymization where possible
- **Data integrity compromise** (flow: Ingest API) — Unauthorized or undetected modification of data in transit or at rest.
  - Mitigations:
    - Cryptographic integrity (HMAC, signatures)
    - Immutable/append-only logs and versioned storage
    - Checksums and validation on ingestion
    - Strong change control and auditing
- **Privacy breaches** (flow: Store) — Sensitive data exposure or over-collection enabling re-identification.
  - Mitigations:
    - Data minimization and purpose limitation
    - Field-level encryption and tokenization
    - Access controls with least privilege
    - Anonymization/pseudonymization where possible
- **Data integrity compromise** (flow: Store) — Unauthorized or undetected modification of data in transit or at rest.
  - Mitigations:
    - Cryptographic integrity (HMAC, signatures)
    - Immutable/append-only logs and versioned storage
    - Checksums and validation on ingestion
    - Strong change control and auditing
- **Privacy breaches** (flow: Events) — Sensitive data exposure or over-collection enabling re-identification.
  - Mitigations:
    - Data minimization and purpose limitation
    - Field-level encryption and tokenization
    - Access controls with least privilege
    - Anonymization/pseudonymization where possible
- **Data integrity compromise** (flow: Events) — Unauthorized or undetected modification of data in transit or at rest.
  - Mitigations:
    - Cryptographic integrity (HMAC, signatures)
    - Immutable/append-only logs and versioned storage
    - Checksums and validation on ingestion
    - Strong change control and auditing
- **Privacy breaches** (flow: Management) — Sensitive data exposure or over-collection enabling re-identification.
  - Mitigations:
    - Data minimization and purpose limitation
    - Field-level encryption and tokenization
    - Access controls with least privilege
    - Anonymization/pseudonymization where possible
- **Data integrity compromise** (flow: Management) — Unauthorized or undetected modification of data in transit or at rest.
  - Mitigations:
    - Cryptographic integrity (HMAC, signatures)
    - Immutable/append-only logs and versioned storage
    - Checksums and validation on ingestion
    - Strong change control and auditing

### Platform

- **Cloud infrastructure vulnerabilities** (asset: Ingestion Service) — Misconfiguration or unpatched components enabling privilege escalation or breach.
  - Mitigations:
    - Least-privilege IAM and role isolation
    - Network segmentation and private endpoints
    - Continuous patching and managed services
    - CSPM, SIEM, and runtime monitoring
- **Cloud infrastructure vulnerabilities** (asset: IoT Hub) — Misconfiguration or unpatched components enabling privilege escalation or breach.
  - Mitigations:
    - Least-privilege IAM and role isolation
    - Network segmentation and private endpoints
    - Continuous patching and managed services
    - CSPM, SIEM, and runtime monitoring
- **Cloud infrastructure vulnerabilities** (asset: Data Lake) — Misconfiguration or unpatched components enabling privilege escalation or breach.
  - Mitigations:
    - Least-privilege IAM and role isolation
    - Network segmentation and private endpoints
    - Continuous patching and managed services
    - CSPM, SIEM, and runtime monitoring
- **Cloud infrastructure vulnerabilities** (asset: Admin Portal) — Misconfiguration or unpatched components enabling privilege escalation or breach.
  - Mitigations:
    - Least-privilege IAM and role isolation
    - Network segmentation and private endpoints
    - Continuous patching and managed services
    - CSPM, SIEM, and runtime monitoring

### Communication

- **Eavesdropping** (flow: Telemetry) — Unencrypted or poorly configured links expose data in transit.
  - Mitigations:
    - TLS 1.2+ with modern ciphers
    - Mutual TLS for device authentication
    - WPA3 or cellular with SIM-based auth
    - Rotate keys; avoid static shared secrets
- **Man-in-the-middle** (flow: Telemetry) — Traffic interception or impersonation between nodes.
  - Mitigations:
    - Certificate pinning and strict hostname verification
    - Mutual TLS and hardware-backed keys
    - Use message authentication (HMAC/MAC) for app-layer integrity
    - Replay protection (nonces, timestamps)
- **Eavesdropping** (flow: Ingest API) — Unencrypted or poorly configured links expose data in transit.
  - Mitigations:
    - TLS 1.2+ with modern ciphers
    - Mutual TLS for device authentication
    - WPA3 or cellular with SIM-based auth
    - Rotate keys; avoid static shared secrets
- **Man-in-the-middle** (flow: Ingest API) — Traffic interception or impersonation between nodes.
  - Mitigations:
    - Certificate pinning and strict hostname verification
    - Mutual TLS and hardware-backed keys
    - Use message authentication (HMAC/MAC) for app-layer integrity
    - Replay protection (nonces, timestamps)
- **Eavesdropping** (flow: Store) — Unencrypted or poorly configured links expose data in transit.
  - Mitigations:
    - TLS 1.2+ with modern ciphers
    - Mutual TLS for device authentication
    - WPA3 or cellular with SIM-based auth
    - Rotate keys; avoid static shared secrets
- **Man-in-the-middle** (flow: Store) — Traffic interception or impersonation between nodes.
  - Mitigations:
    - Certificate pinning and strict hostname verification
    - Mutual TLS and hardware-backed keys
    - Use message authentication (HMAC/MAC) for app-layer integrity
    - Replay protection (nonces, timestamps)
- **Eavesdropping** (flow: Events) — Unencrypted or poorly configured links expose data in transit.
  - Mitigations:
    - TLS 1.2+ with modern ciphers
    - Mutual TLS for device authentication
    - WPA3 or cellular with SIM-based auth
    - Rotate keys; avoid static shared secrets
- **Man-in-the-middle** (flow: Events) — Traffic interception or impersonation between nodes.
  - Mitigations:
    - Certificate pinning and strict hostname verification
    - Mutual TLS and hardware-backed keys
    - Use message authentication (HMAC/MAC) for app-layer integrity
    - Replay protection (nonces, timestamps)
- **Eavesdropping** (flow: Management) — Unencrypted or poorly configured links expose data in transit.
  - Mitigations:
    - TLS 1.2+ with modern ciphers
    - Mutual TLS for device authentication
    - WPA3 or cellular with SIM-based auth
    - Rotate keys; avoid static shared secrets
- **Man-in-the-middle** (flow: Management) — Traffic interception or impersonation between nodes.
  - Mitigations:
    - Certificate pinning and strict hostname verification
    - Mutual TLS and hardware-backed keys
    - Use message authentication (HMAC/MAC) for app-layer integrity
    - Replay protection (nonces, timestamps)

