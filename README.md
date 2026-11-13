# CIS Network Hardening Lab

> **Video demostrativo:** [Ver video del laboratorio](https://youtu.be/LzkHeIqYJ88)

## Descripción
Laboratorio de auditoría y hardening de infraestructura de red mediante un script desarrollado en Python. El proyecto evalúa configuraciones y parámetros de seguridad seleccionados con base en recomendaciones CIS, permite generar una auditoría de solo lectura y, cuando corresponde, aplicar cambios autorizados y ejecutar una auditoría posterior.

**Este proyecto utiliza el script propio `scripts/cis_hardening.py`. No depende de Nessus, CIS-CAT ni de otra herramienta externa de evaluación CIS.**

## Propósito
- Identificar configuraciones inseguras en router, switch y firewall.
- Evaluar controles de seguridad seleccionados y documentar su estado.
- Generar un informe inicial sin modificar los dispositivos.
- Aplicar las reglas seleccionadas mediante el flujo de hardening.
- Generar un informe posterior y comparar los resultados.
- Conservar respaldos, registros y configuraciones para trazabilidad.

## Topología
| Equipo | Dirección |
|---|---|
| Ubuntu Server – auditor Python | `10.23.13.4` |
| Cisco Router R1 | `10.23.13.1` |
| Cisco Switch SW1 | `10.23.13.2` |
| FortiGate FGT-01 | `10.23.13.129` |

![Topología de red]<img width="547" height="467" alt="image" src="https://github.com/user-attachments/assets/f2e5e2a6-b3b9-4edd-bf17-43ef99a8b3c2" />

## Funcionamiento del script
El flujo contempla dos modalidades:

1. **Auditoría (solo lectura):** recopila información, evalúa las reglas configuradas y genera un informe sin aplicar cambios. <img width="1043" height="764" alt="image" src="https://github.com/user-attachments/assets/14873b64-6255-4d5f-b628-2b26cdf5aaab" />


2. **Aplicación y auditoría posterior:** realiza respaldos, aplica las reglas seleccionadas y vuelve a evaluar los dispositivos para generar el informe posterior. <img width="1012" height="747" alt="image" src="https://github.com/user-attachments/assets/e17958fa-98e9-4d2b-a458-0a7e0882e3e2" />

<img width="1574" height="710" alt="image" src="https://github.com/user-attachments/assets/a131eb1a-c9cc-4fdf-a0c0-abc7c15e0f66" />

## Requisitos
- Ubuntu Server con Python 3.
- Conectividad IP desde el servidor auditor hacia los dispositivos.
- Acceso SSH y permisos suficientes para consultar/aplicar configuración.
- Dependencias indicadas en `requirements.txt`.

## Instalación
```bash
git clone <URL_DEL_REPOSITORIO>
cd CIS-Network-Hardening-Lab
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Ejecución
Utiliza los argumentos que soporte la versión real del script. El diseño previsto contempla:
- modo de auditoría sin cambios 
- modo de aplicación con respaldo y auditoría posterior 

## Resultados
- `reports/auditoria-inicial/`: informes de auditoría sin aplicar reglas.
- `reports/auditoria-final/`: informes posteriores al hardening.
- `backups/`: respaldos previos a los cambios.
- `logs/`: registros de ejecución.

Los informes pueden reflejar estados como `PASS`, `FAIL`, `N/A` o `MANUAL`, según los controles realmente implementados.


## Alcance y precisión
La referencia a CIS indica que los controles se seleccionan y documentan tomando como base recomendaciones CIS aplicables al dispositivo. No implica certificación CIS ni cobertura completa de un Benchmark. Documenta para cada control la recomendación de referencia, el criterio técnico, el método de comprobación y el resultado observado.
