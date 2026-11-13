# CIS Network Hardening Lab

> **Video demostrativo:** [Ver video del laboratorio](video/VIDEO_DEMOSTRATIVO.md)

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

![Topología de red](docs/images/topologia.png)

Consulta [la documentación de topología](docs/02-topologia-de-red.md).

## Funcionamiento del script
El flujo contempla dos modalidades:

1. **Auditoría (solo lectura):** recopila información, evalúa las reglas configuradas y genera un informe sin aplicar cambios.
2. **Aplicación y auditoría posterior:** realiza respaldos, aplica las reglas seleccionadas y vuelve a evaluar los dispositivos para generar el informe posterior.

> Ejecuta los cambios únicamente en equipos propios o autorizados. Revisa las reglas y respaldos antes de aplicar cambios en producción.

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

## Configuración
1. Revisa `config/devices.yaml` y adapta los equipos a tu entorno.
2. Revisa `config/rules.yaml` y confirma qué controles están implementados por el script.
3. No guardes contraseñas en archivos versionados. Utiliza variables de entorno o el mecanismo seguro que implemente el script.
4. Copia la versión funcional y probada de `cis_hardening.py` a `scripts/`.

## Ejecución
Utiliza los argumentos que soporte la versión real del script. El diseño previsto contempla:
- modo de auditoría sin cambios (`--audit`);
- modo de aplicación con respaldo y auditoría posterior (`--apply`).

Confirma `python3 scripts/cis_hardening.py --help` antes de ejecutar. No se deben asumir opciones adicionales que no estén implementadas.

## Resultados
- `reports/auditoria-inicial/`: informes de auditoría sin aplicar reglas.
- `reports/auditoria-final/`: informes posteriores al hardening.
- `backups/`: respaldos previos a los cambios.
- `logs/`: registros de ejecución.

Los informes pueden reflejar estados como `PASS`, `FAIL`, `N/A` o `MANUAL`, según los controles realmente implementados.

## Documentación
- [Propósito](docs/01-proposito-del-laboratorio.md)
- [Topología](docs/02-topologia-de-red.md)
- [Metodología](docs/03-metodologia-de-auditoria.md)
- [Recomendaciones CIS](docs/04-recomendaciones-cis.md)
- [Hardening aplicado](docs/05-hardening-aplicado.md)
- [Pruebas y validación](docs/06-pruebas-y-validacion.md)

## Evidencias
Añade capturas reales de la auditoría inicial, aplicación de reglas, auditoría posterior y pruebas de conectividad/administración. No incluyas contraseñas, claves privadas, tokens ni datos sensibles.

## Alcance y precisión
La referencia a CIS indica que los controles se seleccionan y documentan tomando como base recomendaciones CIS aplicables al dispositivo. No implica certificación CIS ni cobertura completa de un Benchmark. Documenta para cada control la recomendación de referencia, el criterio técnico, el método de comprobación y el resultado observado.
