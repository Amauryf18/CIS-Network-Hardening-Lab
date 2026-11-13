# 2. Topología de red

## Inventario
| Dispositivo | IP | Función |
|---|---|---|
| Ubuntu Server | 10.23.13.4 | Servidor auditor Python |
| R1 | 10.23.13.1 | Router |
| SW1 | 10.23.13.2 | Switch |
| FGT-01 | 10.23.13.129 | Firewall |

## Diagrama lógico

```mermaid
flowchart TB
    A[Ubuntu Server<br/>Auditor Python<br/>10.23.13.4]
    R[Cisco Router R1<br/>10.23.13.1]
    S[Cisco Switch SW1<br/>10.23.13.2]
    F[FortiGate FGT-01<br/>10.23.13.129]
    A -->|SSH / auditoría| R
    A -->|SSH / auditoría| S
    A -->|SSH / auditoría| F
    R --- S
    R --- F
```

Adjunta una captura real de GNS3 en `docs/images/topologia.png`.
