# 3. Metodología de auditoría

1. Verificar conectividad y acceso administrativo autorizado.
2. Leer la configuración y el estado de cada dispositivo.
3. Evaluar únicamente los controles definidos en `config/rules.yaml` y soportados por el script.
4. Generar el informe inicial en modo de solo lectura.
5. Revisar los hallazgos y seleccionar cambios autorizados.
6. Crear respaldos antes de modificar configuraciones.
7. Aplicar las reglas habilitadas.
8. Ejecutar nuevamente la auditoría y generar el informe posterior.
9. Comparar resultados y validar que los servicios de red continúen funcionando.

## Estados
- `PASS`: el control cumple el criterio definido.
- `FAIL`: el control no cumple el criterio definido.
- `N/A`: el control no aplica al dispositivo o plataforma.
- `MANUAL`: requiere verificación humana o evidencia que el script no puede confirmar.

Los estados y su significado final deben coincidir con la implementación efectiva del script.
