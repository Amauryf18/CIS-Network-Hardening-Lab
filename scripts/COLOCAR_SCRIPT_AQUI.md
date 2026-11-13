# Script de auditoría

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hardening_audit.py - Auditoría y hardening basados en CIS Benchmark
Dispositivos soportados:
  * Cisco IOS 15.x  (router 7200 y switch IOSv L2)  -> CIS Cisco IOS 15 Benchmark
  * FortiGate FortiOS 7.0.x                          -> CIS FortiGate 7.0.x Benchmark

Modos:
  audit  (por defecto)  Solo lee y genera informe. NO modifica nada.
  apply                 Audita, respalda, aplica las remediaciones, vuelve a auditar
                        y genera el informe póstumo (antes vs. después).

Ejemplos:
  python3 hardening_audit.py -i inventory.json                     # informe, sin cambios
  python3 hardening_audit.py -i inventory.json -m apply --dry-run  # muestra qué haría
  python3 hardening_audit.py -i inventory.json -m apply            # aplica + informe póstumo
  python3 hardening_audit.py -i inventory.json -d R1,FW            # solo algunos equipos
  python3 hardening_audit.py --selftest                            # prueba sin equipos reales
  python3 hardening_audit.py --export-controls-md                  # tabla de controles (Markdown)

Requisitos (en el servidor de auditoría):  Python 3.8+  y  pip install netmiko
"""
import argparse
import datetime
import getpass
import html
import ipaddress
import json
import os
import re
import sys
import tempfile
from pathlib import Path

try:
    from netmiko import ConnectHandler
except ImportError:  # se avisa solo si se intenta una conexión real
    ConnectHandler = None


class Skip(Exception):
    """La remediación no se puede aplicar de forma segura (falta parámetro, riesgo de bloqueo...)."""


# --------------------------------------------------------------------------- #
#  Modelo de controles
# --------------------------------------------------------------------------- #
CONTROLS = []


class Control:
    def __init__(self, cid, platform, ref, title, why, check, fix=None,
                 fixdoc="", roles=None, sev="Media"):
        self.id, self.platform, self.ref, self.title, self.why = cid, platform, ref, title, why
        self.check, self.fix, self.roles, self.sev = check, fix, roles, sev
        if not fixdoc and isinstance(fix, (list, tuple)):
            fixdoc = "; ".join(fix)
        self.fixdoc = fixdoc
        CONTROLS.append(self)

    def applies(self, dev):
        return self.platform == dev["platform"] and (not self.roles or dev.get("role") in self.roles)

    def fix_cmds(self, ctx, dev, params, detail):
        if self.fix is None:
            return None
        if callable(self.fix):
            return self.fix(ctx, dev, params, detail)
        return list(self.fix)


def mask(cmd):
    return re.sub(r"(?i)\b(secret(?: \d)?|password(?: \d)?) (\S+)", r"\1 ****", cmd)


# --------------------------------------------------------------------------- #
#  Cisco IOS - recolección y helpers
# --------------------------------------------------------------------------- #
def collect_cisco(conn):
    run = conn.send_command("show running-config", read_timeout=90).replace("\r", "")
    if not run.endswith("\n"):
        run += "\n"
    keys = conn.send_command("show crypto key mypubkey rsa", read_timeout=30)
    return {"run": run, "keys": keys}


def blocks(run, header_rx):
    """Devuelve [(cabecera, cuerpo)] de bloques de configuración (líneas hijas con sangría)."""
    pat = r"^(" + header_rx + r"[^\n]*)\n((?: [^\n]*\n)*)"
    return [(m.group(1).strip(), m.group(2)) for m in re.finditer(pat, run, re.M)]


def regex_control(cid, ref, title, why, must=None, must_not=None, fix=None,
                  fixdoc="", roles=None, sev="Media"):
    def check(ctx, dev, p):
        run, bad = ctx["run"], []
        for rx in must or []:
            if not re.search(rx, run, re.M):
                bad.append("No encontrado: /%s/" % rx)
        for rx in must_not or []:
            m = re.search(rx, run, re.M)
            if m:
                bad.append("Presente: '%s'" % m.group(0).strip())
        return ("FAIL", "; ".join(bad)) if bad else ("PASS", "Cumple")
    return Control(cid, "cisco_ios", ref, title, why, check, fix, fixdoc, roles, sev)


def need_param(p, name, human):
    v = p.get(name)
    if not v:
        raise Skip("Falta el parámetro '%s' (%s) en el inventario" % (name, human))
    return v


# ---- Plano de gestión: identidad, SSH ------------------------------------- #
def _chk_hostname(ctx, dev, p):
    m = re.search(r"^hostname (\S+)", ctx["run"], re.M)
    if not m or m.group(1).lower() in ("router", "switch"):
        return "FAIL", "Hostname por defecto o ausente (%s)" % (m.group(1) if m else "-")
    return "PASS", "hostname=%s" % m.group(1)


def _fix_hostname(ctx, dev, p, d):
    name = dev.get("hostname") or dev["name"]
    if name.lower() in ("router", "switch"):
        raise Skip("Defina 'hostname' distinto del valor por defecto en el inventario")
    return ["hostname %s" % name]


Control("IOS-01", "cisco_ios", "CIS IOS 15 - 2.1.1.1.1", "Definir un 'hostname' distinto del valor por defecto",
        "El nombre por defecto impide identificar el equipo en logs/alertas y IOS lo exige para generar claves RSA (SSH).",
        _chk_hostname, _fix_hostname, "hostname <nombre>", sev="Baja")

regex_control("IOS-02", "CIS IOS 15 - 2.1.1.1.2", "Definir 'ip domain name'",
              "Necesario junto al hostname para generar la clave RSA; sin ella no hay SSH.",
              must=[r"^ip domain[ -]name \S+"],
              fix=lambda c, d, p, x: ["ip domain name %s" % p.get("domain_name", "lab.local")],
              fixdoc="ip domain name <dominio>", sev="Baja")


def _chk_rsa(ctx, dev, p):
    m = re.search(r"Key Data:\s*\n\s*([0-9A-Fa-f]{8})", ctx["keys"])
    if not m:
        return "FAIL", "No hay clave RSA generada"
    if int(m.group(1), 16) < 0x30820122:  # cabecera DER de RSA-2048
        return "FAIL", "Clave RSA menor a 2048 bits"
    return "PASS", "Clave RSA >= 2048 bits"


Control("IOS-03", "cisco_ios", "CIS IOS 15 - 2.1.1.1.3", "Clave RSA con módulo >= 2048 bits",
        "Claves de 1024 bits o menos son factorizables a mediano plazo; SSH v2 debe apoyarse en 2048+.",
        _chk_rsa, ["!EXEC crypto key generate rsa modulus 2048"],
        "crypto key generate rsa modulus 2048", sev="Alta")

regex_control("IOS-04", "CIS IOS 15 - 2.1.1.2", "Forzar SSH versión 2",
              "SSH v1 tiene debilidades criptográficas conocidas (ataques de inserción y MITM).",
              must=[r"^ip ssh version 2"], fix=["ip ssh version 2"], sev="Alta")

regex_control("IOS-05", "CIS IOS 15 - 2.1.1.1.4/5", "SSH: time-out <= 60 s y authentication-retries <= 3",
              "Limita la ventana para ataques de fuerza bruta y sesiones SSH a medio abrir.",
              must=[r"^ip ssh time-out (?:[1-9]|[1-5]\d|60)\s*$", r"^ip ssh authentication-retries [1-3]\s*$"],
              fix=["ip ssh time-out 60", "ip ssh authentication-retries 3"])


# ---- AAA / contraseñas ----------------------------------------------------- #
def _fix_aaa(ctx, dev, p, d):
    if not re.search(r"^username %s\s" % re.escape(dev["username"]), ctx["run"], re.M):
        raise Skip("El usuario '%s' no existe como usuario local; créelo antes de activar AAA "
                   "(si no, quedaría bloqueado)" % dev["username"])
    return ["aaa new-model", "aaa authentication login default local"]


regex_control("IOS-06", "CIS IOS 15 - 1.1.1 / 1.1.2", "Habilitar AAA ('aaa new-model' + autenticación login)",
              "Centraliza la autenticación y es la base para accounting/TACACS+. Sin AAA se usan contraseñas de línea compartidas.",
              must=[r"^aaa new-model", r"^aaa authentication login default"],
              fix=_fix_aaa, fixdoc="aaa new-model; aaa authentication login default local", sev="Alta")

regex_control("IOS-07", "CIS IOS 15 - 1.4.3", "Usuarios locales con 'secret' (no 'password')",
              "'password' se guarda en texto claro o cifrado reversible (tipo 7); 'secret' usa hash.",
              must_not=[r"^username \S+ .*\bpassword\b"],
              fix=None, fixdoc="MANUAL: username <u> privilege 15 secret <pwd>", sev="Alta")


def _fix_enable(ctx, dev, p, d):
    cmds = []
    if re.search(r"^enable password", ctx["run"], re.M):
        cmds.append("no enable password")
    if not re.search(r"^enable secret", ctx["run"], re.M):
        pw = os.environ.get(p.get("enable_secret_env", "NEW_ENABLE_SECRET"))
        if not pw:
            raise Skip("Defina la variable de entorno %s con el nuevo 'enable secret'"
                       % p.get("enable_secret_env", "NEW_ENABLE_SECRET"))
        cmds.append("enable secret %s" % pw)
    return cmds


regex_control("IOS-08", "CIS IOS 15 - 1.4.1", "Usar 'enable secret' y eliminar 'enable password'",
              "'enable password' se almacena reversible; 'enable secret' guarda un hash.",
              must=[r"^enable secret"], must_not=[r"^enable password"],
              fix=_fix_enable, fixdoc="enable secret <pwd>; no enable password", sev="Alta")

regex_control("IOS-09", "CIS IOS 15 - 1.4.2", "Habilitar 'service password-encryption'",
              "Evita que contraseñas de línea queden legibles en el running-config (mitigación de 'shoulder surfing' y backups expuestos).",
              must=[r"^service password-encryption"], fix=["service password-encryption"])


# ---- Líneas de acceso ------------------------------------------------------ #
def _chk_vty_transport(ctx, dev, p):
    bad = [h for h, b in blocks(ctx["run"], r"line vty")
           if not re.search(r"^ transport input (ssh|none)\s*$", b, re.M)]
    return ("FAIL", "Líneas sin 'transport input ssh': %s" % ", ".join(bad)) if bad else ("PASS", "Solo SSH en VTY")


def _fix_vty_transport(ctx, dev, p, d):
    if dev.get("protocol", "ssh") == "telnet":
        raise Skip("El script está conectado por Telnet; cambie 'protocol' a ssh (y valide SSH) antes de restringir VTY")
    cmds = []
    for h, b in blocks(ctx["run"], r"line vty"):
        if not re.search(r"^ transport input (ssh|none)\s*$", b, re.M):
            cmds += [h, "transport input ssh"]
    return cmds


Control("IOS-10", "cisco_ios", "CIS IOS 15 - 1.2.2", "VTY: 'transport input ssh'",
        "Telnet envía credenciales y comandos en claro; solo SSH protege la sesión de administración.",
        _chk_vty_transport, _fix_vty_transport, "line vty 0 4 / transport input ssh", sev="Alta")


def _timeout_ok(body):
    m = re.search(r"^ exec-timeout (\d+)(?: (\d+))?", body, re.M)
    if not m:
        return True  # por defecto IOS = 10 min
    total = int(m.group(1)) * 60 + int(m.group(2) or 0)
    return 0 < total <= 600


def _timeout_control(cid, ref, title, hdr, label):
    def check(ctx, dev, p):
        bad = [h for h, b in blocks(ctx["run"], hdr) if not _timeout_ok(b)]
        return ("FAIL", "exec-timeout inválido en: %s" % ", ".join(bad)) if bad else ("PASS", "exec-timeout <= 10 min")

    def fix(ctx, dev, p, d):
        cmds = []
        for h, b in blocks(ctx["run"], hdr):
            if not _timeout_ok(b):
                cmds += [h, "exec-timeout 10 0"]
        return cmds
    Control(cid, "cisco_ios", ref, title,
            "Una sesión administrativa abandonada con 'exec-timeout 0 0' queda abierta indefinidamente y puede ser secuestrada.",
            check, fix, "%s / exec-timeout 10 0" % label)


_timeout_control("IOS-11", "CIS IOS 15 - 1.2.7", "Consola: exec-timeout <= 10 min", r"line con 0", "line con 0")
_timeout_control("IOS-12", "CIS IOS 15 - 1.2.8", "VTY: exec-timeout <= 10 min", r"line vty", "line vty 0 4")


def _chk_vty_acl(ctx, dev, p):
    bad = [h for h, b in blocks(ctx["run"], r"line vty") if not re.search(r"^ access-class \S+ in", b, re.M)]
    return ("FAIL", "VTY sin access-class: %s" % ", ".join(bad)) if bad else ("PASS", "access-class en todas las VTY")


def _fix_vty_acl(ctx, dev, p, d):
    audit = need_param(p, "audit_server_ip", "IP del servidor de auditoría que debe seguir pudiendo entrar")
    cmds = ["ip access-list standard VTY-ACL", "permit host %s" % audit]
    cmds += ["permit %s" % x for x in p.get("mgmt_permit", [])]
    cmds += ["deny any log"]
    for h, b in blocks(ctx["run"], r"line vty"):
        if not re.search(r"^ access-class \S+ in", b, re.M):
            cmds += [h, "access-class VTY-ACL in"]
    return cmds


Control("IOS-13", "cisco_ios", "CIS IOS 15 - 1.2.4 / 1.2.5", "VTY: ACL de acceso (solo gestión autorizada)",
        "Reduce la superficie: solo el servidor de auditoría y la red de gestión pueden iniciar sesión de administración.",
        _chk_vty_acl, _fix_vty_acl, "ip access-list standard VTY-ACL (permit gestión, deny any log) / access-class VTY-ACL in",
        sev="Alta")

regex_control("IOS-14", "CIS IOS 15 - 1.3.2", "Banner de advertencia legal ('banner login')",
              "Aviso legal de acceso no autorizado: requisito normativo y base para acciones legales.",
              must=[r"^banner (login|motd|exec)"],
              fix=lambda c, d, p, x: ["banner login #%s#" % p.get(
                  "banner_text", "ACCESO RESTRINGIDO. Solo personal autorizado. La actividad es monitoreada.").replace("#", "")],
              fixdoc="banner login #<texto>#", sev="Baja")

# ---- Servicios globales ---------------------------------------------------- #
regex_control("IOS-15", "CIS IOS 15 - 2.1 (HTTP)", "Deshabilitar servidor HTTP/HTTPS del dispositivo",
              "El servidor web integrado amplía la superficie de ataque (vulnerabilidades históricas de IOS HTTP).",
              must_not=[r"^ip http (secure-)?server"], fix=["no ip http server", "no ip http secure-server"])


def _fix_snmp(ctx, dev, p, d):
    cmds = []
    for m in re.finditer(r"^snmp-server community (\S+)(.*)$", ctx["run"], re.M):
        if m.group(1).lower() in ("public", "private") or re.search(r"\bRW\b", m.group(2)):
            cmds.append("no snmp-server community %s" % m.group(1))
    return cmds


def _chk_snmp(ctx, dev, p):
    bad = [m.group(0).strip() for m in re.finditer(r"^snmp-server community (\S+)(.*)$", ctx["run"], re.M)
           if m.group(1).lower() in ("public", "private") or re.search(r"\bRW\b", m.group(2))]
    return ("FAIL", "Comunidades inseguras: %s" % " | ".join(bad)) if bad else ("PASS", "Sin comunidades public/private/RW")


Control("IOS-16", "cisco_ios", "CIS IOS 15 - 1.5.2 / 1.5.3", "SNMP: sin comunidades 'public'/'private' ni RW",
        "Las comunidades por defecto son las primeras que prueba un atacante y 'RW' permite modificar la configuración.",
        _chk_snmp, _fix_snmp, "no snmp-server community <public|private|RW>", sev="Alta")

regex_control("IOS-17", "CIS IOS 15 - 2.1.2", "Deshabilitar CDP ('no cdp run')",
              "CDP revela modelo, IOS, IPs y topología a cualquier vecino de capa 2.",
              must=[r"^no cdp run"], fix=["no cdp run"])
regex_control("IOS-18", "CIS IOS 15 - 2.1.3", "Deshabilitar BOOTP ('no ip bootp server')",
              "Servicio heredado innecesario que puede servir configuraciones/imágenes.",
              must=[r"^no ip bootp server"], fix=["no ip bootp server"])
regex_control("IOS-19", "CIS IOS 15 - 3.1.1", "Deshabilitar 'ip source-route'",
              "El enrutamiento por origen permite a un atacante eludir controles y dirigir tráfico por rutas elegidas.",
              must=[r"^no ip source-route"], fix=["no ip source-route"])
regex_control("IOS-20", "CIS IOS 15 - 2.1 (PAD)", "Deshabilitar 'service pad'",
              "PAD (X.25) es un servicio heredado sin uso.", must=[r"^no service pad"], fix=["no service pad"], sev="Baja")
regex_control("IOS-21", "CIS IOS 15 - 2.1 (DNS lookup)", "Deshabilitar 'ip domain-lookup'",
              "Evita que comandos mal escritos disparen consultas DNS (fuga de información y bloqueos de consola).",
              must=[r"^no ip domain[ -]lookup"], fix=["no ip domain-lookup"], sev="Baja")

# ---- Logging / NTP --------------------------------------------------------- #
regex_control("IOS-22", "CIS IOS 15 - 2.2.5", "Marcas de tiempo en logs y debug (datetime msec)",
              "Sin marca de tiempo los logs no sirven para correlación forense de incidentes.",
              must=[r"^service timestamps log datetime", r"^service timestamps debug datetime"],
              fix=["service timestamps log datetime msec", "service timestamps debug datetime msec"])
regex_control("IOS-23", "CIS IOS 15 - 2.2.2", "Logging buffered con tamaño definido",
              "Conserva eventos localmente si el servidor syslog no está disponible.",
              must=[r"^logging buffered \d+"], fix=["logging buffered 64000"], sev="Baja")
regex_control("IOS-24", "CIS IOS 15 - 2.2.4 / 2.2.7", "Enviar logs a servidor syslog externo",
              "Los logs locales pueden ser borrados por un atacante; el servidor de auditoría los conserva.",
              must=[r"^logging (host )?\d+\.\d+\.\d+\.\d+"],
              fix=lambda c, d, p, x: ["logging host %s" % need_param(p, "syslog_host", "IP del servidor syslog"),
                                      "logging trap informational"],
              fixdoc="logging host <ip>; logging trap informational")
regex_control("IOS-25", "CIS IOS 15 - 2.3", "Sincronización horaria (NTP)",
              "Hora correcta es imprescindible para logs confiables y validación de certificados.",
              must=[r"^ntp server"],
              fix=lambda c, d, p, x: ["ntp server %s" % need_param(p, "ntp_server", "IP del servidor NTP")],
              fixdoc="ntp server <ip>", sev="Baja")

# ---- Switch / interfaces --------------------------------------------------- #
regex_control("IOS-26", "CIS/Cisco L2 - BPDU Guard", "Switch: 'spanning-tree portfast bpduguard default'",
              "Apaga puertos de acceso que reciban BPDUs: evita que un switch pirata manipule el árbol STP.",
              must=[r"^spanning-tree portfast bpduguard default"],
              fix=["spanning-tree portfast bpduguard default"], roles=["switch"])


def _iface_control(cid, ref, title, why, line):
    def bad_ifaces(run):
        out = []
        for h, b in blocks(run, "interface"):
            if (re.search(r"^ ip address (\d|dhcp)", b, re.M) and not re.search(r"^ shutdown", b, re.M)
                    and not re.search(r"^ %s\s*$" % re.escape(line), b, re.M)):
                out.append(h.split()[1])
        return out

    def check(ctx, dev, p):
        bad = bad_ifaces(ctx["run"])
        return ("FAIL", "Interfaces sin '%s': %s" % (line, ", ".join(bad))) if bad else ("PASS", "Cumple en todas las interfaces L3")

    def fix(ctx, dev, p, d):
        cmds = []
        for n in bad_ifaces(ctx["run"]):
            cmds += ["interface %s" % n, line]
        return cmds
    Control(cid, "cisco_ios", ref, title, why, check, fix, "interface <x> / %s" % line, roles=["router", "switch"])


_iface_control("IOS-27", "CIS IOS 15 - 3.1.2", "Interfaces L3: 'no ip proxy-arp'",
               "Proxy ARP permite que el router responda por hosts remotos, facilitando suplantación y expansión de dominios ARP.",
               "no ip proxy-arp")
_iface_control("IOS-28", "CIS/Cisco - ICMP redirects", "Interfaces L3: 'no ip redirects'",
               "Los ICMP redirect pueden usarse para alterar la tabla de rutas de un host.",
               "no ip redirects")


# --------------------------------------------------------------------------- #
#  FortiGate - recolección y helpers
# --------------------------------------------------------------------------- #
def parse_kv(text):
    d = {}
    for line in text.splitlines():
        m = re.match(r"^\s*([\w\-]+)\s*:\s*(.*?)\s*$", line)
        if m:
            d[m.group(1)] = m.group(2)
    return d


def collect_forti(conn):
    g = lambda c: conn.send_command(c, read_timeout=60)
    return {"global": parse_kv(g("get system global")),
            "pw": parse_kv(g("get system password-policy")),
            "syslog": parse_kv(g("get log syslogd setting")),
            "ntp": parse_kv(g("get system ntp")),
            "snmp": g("show system snmp community"),
            "admin": g("show system admin"),
            "iface": g("show system interface")}


def _int(x):
    try:
        return int(str(x).split()[0])
    except (ValueError, IndexError):
        return None


def eq(v):
    return (lambda x: x is not None and x.strip().strip('"') == v), v


def rng(lo, hi):
    return (lambda x: _int(x) is not None and lo <= _int(x) <= hi), "%d..%d" % (lo, hi)


def ge(n):
    return (lambda x: _int(x) is not None and _int(x) >= n), ">=%d" % n


def no_legacy_tls():
    return (lambda x: x is not None and not re.search(r"sslv3|tlsv1-0|tlsv1-1", x)), "solo tlsv1-2/tlsv1-3"


def fgt_settings(cid, ref, title, why, src, path, rules, sev="Media"):
    """rules: [(clave, (predicado, descripción), valor_a_configurar)]"""
    def check(ctx, dev, p):
        bad = []
        for key, (pred, desc), _ in rules:
            val = ctx[src].get(key)
            if not pred(val):
                bad.append("%s=%s (esperado %s)" % (key, val, desc))
        return ("FAIL", "; ".join(bad)) if bad else ("PASS", "Cumple")

    cmds = ["config %s" % path] + ["set %s %s" % (k, v) for k, _, v in rules] + ["end"]
    Control(cid, "fortigate", ref, title, why, check, cmds, "; ".join(cmds), sev=sev)


fgt_settings("FGT-01", "CIS FortiGate 7.0 - Administración", "Deshabilitar Telnet administrativo",
             "Telnet transmite credenciales en claro; la administración debe ser solo HTTPS/SSH.",
             "global", "system global", [("admin-telnet", eq("disable"), "disable")], sev="Alta")
fgt_settings("FGT-02", "CIS FortiGate 7.0 - Administración", "Timeout de inactividad de administración <= 5 min",
             "Reduce el riesgo de sesiones administrativas desatendidas.",
             "global", "system global", [("admintimeout", rng(1, 5), 5)])
fgt_settings("FGT-03", "CIS FortiGate 7.0 - Administración", "Bloqueo de cuenta: 3 intentos / 900 s",
             "Mitiga ataques de fuerza bruta contra el login administrativo.",
             "global", "system global",
             [("admin-lockout-threshold", rng(1, 3), 3), ("admin-lockout-duration", ge(900), 900)], sev="Alta")
fgt_settings("FGT-04", "CIS FortiGate 7.0 - Banners", "Habilitar banner pre-login y post-login",
             "Aviso legal de acceso restringido antes y después de autenticarse.",
             "global", "system global",
             [("pre-login-banner", eq("enable"), "enable"), ("post-login-banner", eq("enable"), "enable")], sev="Baja")
fgt_settings("FGT-05", "CIS FortiGate 7.0 - Criptografía", "Habilitar 'strong-crypto'",
             "Fuerza suites de cifrado y protocolos fuertes en HTTPS/SSH/SSL-VPN.",
             "global", "system global", [("strong-crypto", eq("enable"), "enable")], sev="Alta")
fgt_settings("FGT-06", "CIS FortiGate 7.0 - Criptografía", "GUI administrativa solo con TLS 1.2/1.3",
             "TLS 1.0/1.1 y SSLv3 tienen vulnerabilidades conocidas (POODLE, BEAST).",
             "global", "system global",
             [("admin-https-ssl-versions", no_legacy_tls(), "tlsv1-2 tlsv1-3")], sev="Alta")
fgt_settings("FGT-07", "CIS FortiGate 7.0 - Criptografía", "Deshabilitar SSH v1 administrativo",
             "SSH v1 es inseguro.", "global", "system global", [("admin-ssh-v1", eq("disable"), "disable")], sev="Alta")
fgt_settings("FGT-08", "CIS FortiGate 7.0 - Política de contraseñas", "Política de contraseñas robusta",
             "Obliga a contraseñas de administradores con longitud >= 8, mayúscula, minúscula, número y símbolo.",
             "pw", "system password-policy",
             [("status", eq("enable"), "enable"), ("minimum-length", ge(8), 8),
              ("min-upper-case-letter", ge(1), 1), ("min-lower-case-letter", ge(1), 1),
              ("min-number", ge(1), 1), ("min-non-alphanumeric", ge(1), 1)], sev="Alta")


def _fgt_syslog_fix(ctx, dev, p, d):
    host = need_param(p, "syslog_host", "IP del servidor syslog")
    return ["config log syslogd setting", "set status enable", "set server %s" % host, "end"]


Control("FGT-09", "fortigate", "CIS FortiGate 7.0 - Logging", "Enviar logs a servidor syslog externo",
        "Conserva evidencia fuera del equipo; un atacante no puede borrarla.",
        lambda c, d, p: ("PASS", "Cumple") if eq("enable")[0](c["syslog"].get("status"))
        else ("FAIL", "status=%s" % c["syslog"].get("status")),
        _fgt_syslog_fix, "config log syslogd setting / set status enable / set server <ip>")


def _fgt_ntp_fix(ctx, dev, p, d):
    host = need_param(p, "ntp_server", "IP del servidor NTP")
    return ["config system ntp", "set ntpsync enable", "set type custom", "config ntpserver", "edit 1",
            "set server %s" % host, "next", "end", "end"]


Control("FGT-10", "fortigate", "CIS FortiGate 7.0 - Hora", "Sincronización horaria NTP habilitada",
        "Logs con hora confiable.",
        lambda c, d, p: ("PASS", "Cumple") if eq("enable")[0](c["ntp"].get("ntpsync"))
        else ("FAIL", "ntpsync=%s" % c["ntp"].get("ntpsync")),
        _fgt_ntp_fix, "config system ntp / set ntpsync enable / set type custom / config ntpserver ...", sev="Baja")


def _admins(text):
    return re.findall(r'edit "([^"]+)"(.*?)\n\s*next', text, re.S)


def _bad_trusthost(ctx):
    return [n for n, b in _admins(ctx["admin"])
            if not re.search(r"set trusthost1 (?!0\.0\.0\.0 0\.0\.0\.0)\S+", b)]


def _chk_trusthost(ctx, dev, p):
    bad = _bad_trusthost(ctx)
    return ("FAIL", "Administradores sin trusthost: %s" % ", ".join(bad)) if bad else ("PASS", "Todos con trusthost")


def _fix_trusthost(ctx, dev, p, d):
    net = ipaddress.ip_network(need_param(p, "fortigate_trusthost", "red de gestión, p.ej. 10.0.0.0/24"), strict=False)
    audit = ipaddress.ip_address(need_param(p, "audit_server_ip", "IP del servidor de auditoría"))
    if audit not in net:
        raise Skip("audit_server_ip %s no está dentro de %s: quedaría bloqueado" % (audit, net))
    cmds = ["config system admin"]
    for n in _bad_trusthost(ctx):
        cmds += ['edit "%s"' % n, "set trusthost1 %s %s" % (net.network_address, net.netmask), "next"]
    return cmds + ["end"]


Control("FGT-11", "fortigate", "CIS FortiGate 7.0 - Administración", "Restringir administradores con 'trusthost'",
        "Un administrador sin trusthost puede autenticarse desde cualquier IP; limitarlo reduce la exposición.",
        _chk_trusthost, _fix_trusthost, 'config system admin / edit "<u>" / set trusthost1 <red> <máscara>', sev="Alta")


def _chk_snmp_fgt(ctx, dev, p):
    return ("FAIL", "Existen comunidades SNMP v1/v2c") if re.search(r"edit \d+", ctx["snmp"]) else ("PASS", "Sin comunidades v1/v2c")


Control("FGT-12", "fortigate", "CIS FortiGate 7.0 - SNMP", "Usar solo SNMPv3 (sin comunidades v1/v2c)",
        "v1/v2c envían la comunidad en claro y sin cifrado.",
        _chk_snmp_fgt, None, "MANUAL: eliminar comunidades y crear 'config system snmp user' con auth/priv", sev="Alta")


def _iface_blocks(text):
    return re.findall(r'edit "([^"]+)"(.*?)\n\s*next', text, re.S)


def _chk_wan(ctx, dev, p):
    bad = []
    for n, b in _iface_blocks(ctx["iface"]):
        if re.search(r"set role wan", b):
            m = re.search(r"set allowaccess (.*)", b)
            risky = set((m.group(1) if m else "").split()) & {"http", "telnet", "snmp"}
            if risky:
                bad.append("%s (%s)" % (n, ",".join(sorted(risky))))
    return ("FAIL", "Gestión insegura en WAN: %s" % "; ".join(bad)) if bad else ("PASS", "Sin http/telnet/snmp en WAN")


Control("FGT-13", "fortigate", "CIS FortiGate 7.0 - Interfaces", "Sin servicios de gestión inseguros (http/telnet/snmp) en WAN",
        "Exponer gestión insegura a Internet es uno de los vectores de compromiso más comunes en firewalls.",
        _chk_wan, None, "MANUAL: set allowaccess ping https ssh (según interfaz; riesgo de perder acceso)", sev="Alta")


# --------------------------------------------------------------------------- #
#  Conexión y aplicación
# --------------------------------------------------------------------------- #
ERR_CISCO = re.compile(r"^% (Invalid|Incomplete|Ambiguous|Please|Bad|Cannot|Unrecognized|Access)", re.M)
ERR_FGT = re.compile(r"(?i)command fail|unknown action|parse error|not found|invalid|fail")


def cred(dev, key):
    if dev.get(key):
        return dev[key]
    env = dev.get(key + "_env")
    if env and os.environ.get(env):
        return os.environ[env]
    return None


def real_connect(dev):
    if ConnectHandler is None:
        sys.exit("Falta netmiko. Instale con:  pip install netmiko")
    pw = cred(dev, "password") or getpass.getpass("Contraseña de %s@%s: " % (dev["username"], dev["name"]))
    if dev["platform"] == "fortigate":
        dtype = "fortinet"
    else:
        dtype = "cisco_ios_telnet" if dev.get("protocol", "ssh") == "telnet" else "cisco_ios"
    conn = ConnectHandler(device_type=dtype, host=dev["host"], username=dev["username"], password=pw,
                          secret=cred(dev, "secret") or pw, timeout=30, fast_cli=False)
    if dev["platform"] == "cisco_ios":
        conn.enable()
    return conn


def run_exec(conn, cmd):
    out = conn.send_command_timing(cmd, read_timeout=180)
    for _ in range(4):
        if re.search(r"\[yes/no\]|\[confirm\]", out):
            out += conn.send_command_timing("yes", read_timeout=180)
        else:
            break
    return out


def apply_cmds(dev, conn, cmds):
    """Devuelve (salida, errores)."""
    out = ""
    if dev["platform"] == "fortigate":
        out = conn.send_config_set(cmds)
        errs = [l for l in out.splitlines() if ERR_FGT.search(l) and not l.strip().startswith("set ")]
        return out, errs
    buf = []
    for c in cmds:
        if c.startswith("!EXEC "):
            if buf:
                out += conn.send_config_set(buf)
                buf = []
            out += run_exec(conn, c[6:])
        else:
            buf.append(c)
    if buf:
        out += conn.send_config_set(buf)
    return out, ERR_CISCO.findall(out) and [l for l in out.splitlines() if ERR_CISCO.match(l)]


def evaluate(controls, ctx, dev, params):
    res = {}
    for c in controls:
        try:
            res[c.id] = c.check(ctx, dev, params)
        except Exception as e:  # un control defectuoso no debe tumbar la auditoría
            res[c.id] = ("ERROR", "%s: %s" % (type(e).__name__, e))
    return res


def process_device(dev, params, mode, dry, selected, factory, outdir):
    conn = factory(dev)
    collector = collect_cisco if dev["platform"] == "cisco_ios" else collect_forti
    controls = [c for c in CONTROLS if c.applies(dev) and (not selected or c.id in selected)]
    try:
        ctx = collector(conn)
        before = evaluate(controls, ctx, dev, params)
        recs = {c.id: {"id": c.id, "ref": c.ref, "title": c.title, "why": c.why, "sev": c.sev,
                       "fixdoc": c.fixdoc, "before": before[c.id], "after": None,
                       "fix_status": "n/a", "commands": [], "output": ""} for c in controls}
        after = None
        if mode == "apply":
            bdir = Path(outdir) / "backups"
            bdir.mkdir(parents=True, exist_ok=True)
            if dev["platform"] == "cisco_ios":
                (bdir / ("%s_running-config.txt" % dev["name"])).write_text(ctx["run"])
            else:
                (bdir / ("%s_full-config.txt" % dev["name"])).write_text(
                    conn.send_command("show full-configuration", read_timeout=120))
            changed = False
            for c in controls:
                r = recs[c.id]
                if before[c.id][0] != "FAIL":
                    continue
                try:
                    cmds = c.fix_cmds(ctx, dev, params, before[c.id][1])
                except Skip as s:
                    r["fix_status"] = "OMITIDO: %s" % s
                    continue
                if cmds is None:
                    r["fix_status"] = "MANUAL"
                    continue
                if not cmds:
                    r["fix_status"] = "n/a"
                    continue
                r["commands"] = [mask(x) for x in cmds]
                if dry:
                    r["fix_status"] = "SIMULADO (dry-run)"
                    continue
                out, errs = apply_cmds(dev, conn, cmds)
                r["output"] = mask(out)[-1500:]
                r["fix_status"] = ("ERROR: " + " | ".join(errs[:3])) if errs else "APLICADO"
                changed = changed or not errs
            if changed and dev["platform"] == "cisco_ios":
                conn.send_command("write memory", read_timeout=60)
            if not dry:
                ctx2 = collector(conn)
                after = evaluate(controls, ctx2, dev, params)
                for cid, v in after.items():
                    recs[cid]["after"] = v
        return {"name": dev["name"], "role": dev.get("role", ""), "platform": dev["platform"], "host": dev["host"],
                "controls": [recs[c.id] for c in controls], "has_after": after is not None}
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass


# --------------------------------------------------------------------------- #
#  Informes
# --------------------------------------------------------------------------- #
def score(items, key):
    vals = [i[key][0] for i in items if i[key]]
    n = len(vals)
    return (vals.count("PASS"), n, (100.0 * vals.count("PASS") / n) if n else 0.0)


def build_html(report):
    esc = html.escape
    css = ("body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1b1b1b}h1{margin-bottom:0}"
           "table{border-collapse:collapse;width:100%;margin:8px 0 28px}th,td{border:1px solid #ccc;padding:6px 8px;"
           "font-size:13px;vertical-align:top}th{background:#263238;color:#fff}.PASS{background:#d8f3dc}"
           ".FAIL{background:#ffd6d6}.ERROR{background:#ffe8a3}.MANUAL,.OMITIDO{background:#fff3cd}"
           "code{font-size:12px;background:#f2f2f2;padding:1px 3px}small{color:#555}")
    h = ["<html><head><meta charset='utf-8'><title>Informe CIS</title><style>%s</style></head><body>" % css,
         "<h1>Informe de cumplimiento CIS</h1><p>Modo: <b>%s</b>%s &nbsp;|&nbsp; Fecha: %s</p>" % (
             esc(report["mode"]), " (dry-run)" if report["dry_run"] else "", esc(report["timestamp"]))]
    for d in report["devices"]:
        pb, n, pctb = score(d["controls"], "before")
        h.append("<h2>%s <small>(%s, %s, %s)</small></h2>" % (esc(d["name"]), esc(d["role"]), esc(d["platform"]), esc(d["host"])))
        line = "Cumplimiento inicial: <b>%d/%d (%.0f%%)</b>" % (pb, n, pctb)
        if d["has_after"]:
            pa, _, pcta = score(d["controls"], "after")
            line += " &rarr; final: <b>%d/%d (%.0f%%)</b>" % (pa, n, pcta)
        h.append("<p>%s</p>" % line)
        h.append("<table><tr><th>ID</th><th>Ref. CIS</th><th>Control</th><th>Sev.</th><th>Antes</th>"
                 "%s<th>Remediación</th><th>Por qué</th></tr>" % ("<th>Después</th>" if d["has_after"] else ""))
        for c in d["controls"]:
            b = c["before"]
            row = "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class='%s'><b>%s</b><br><small>%s</small></td>" % (
                esc(c["id"]), esc(c["ref"]), esc(c["title"]), esc(c["sev"]), b[0], b[0], esc(b[1]))
            if d["has_after"]:
                a = c["after"] or ("-", "")
                row += "<td class='%s'><b>%s</b><br><small>%s</small></td>" % (a[0], a[0], esc(a[1]))
            cmds = "<br>".join("<code>%s</code>" % esc(x) for x in c["commands"]) or "<code>%s</code>" % esc(c["fixdoc"])
            fs = c["fix_status"]
            row += "<td><b>%s</b><br>%s</td><td>%s</td></tr>" % (esc(fs), cmds, esc(c["why"]))
            h.append(row)
        h.append("</table>")
    h.append("</body></html>")
    return "\n".join(h)


def write_reports(report, outdir):
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    stem = "informe_%s" % report["mode"]
    (out / (stem + ".json")).write_text(json.dumps(report, indent=2, ensure_ascii=False))
    (out / (stem + ".html")).write_text(build_html(report), encoding="utf-8")
    return out / (stem + ".html"), out / (stem + ".json")


def print_summary(report):
    for d in report["devices"]:
        pb, n, pctb = score(d["controls"], "before")
        s = "%-6s antes: %2d/%d (%3.0f%%)" % (d["name"], pb, n, pctb)
        if d["has_after"]:
            pa, _, pcta = score(d["controls"], "after")
            s += "   después: %2d/%d (%3.0f%%)" % (pa, n, pcta)
        print(s)
        for c in d["controls"]:
            st = c["after"][0] if c["after"] else c["before"][0]
            if st != "PASS":
                print("    [%s] %s %s  -> %s" % (st, c["id"], c["title"], c["fix_status"]))


# --------------------------------------------------------------------------- #
#  Simulación para pruebas sin equipos (--selftest)
# --------------------------------------------------------------------------- #
class FakeCisco:
    NESTED = ("transport input", "exec-timeout", "access-class", "no ip proxy-arp", "no ip redirects", "permit ", "deny ")
    REPLACE = ("hostname", "enable secret", "ip domain name", "ip ssh time-out", "ip ssh authentication-retries",
               "ip ssh version", "logging buffered", "banner", "ntp server", "logging host")

    def __init__(self, text):
        self.glob, self.blk, self.keys = [], {}, ""
        cur = None
        for l in text.splitlines():
            if not l.strip() or l.strip() == "!":
                cur = None
            elif l.startswith(" "):
                if cur:
                    self.blk[cur].append(l.rstrip())
            elif re.match(r"(interface|line|ip access-list) ", l):
                cur = l.strip()
                self.blk.setdefault(cur, [])
            else:
                cur = None
                self.glob.append(l.strip())

    def enable(self): pass
    def disconnect(self): pass

    def render(self):
        s = "\n".join(self.glob) + "\n!\n"
        for h, b in self.blk.items():
            s += h + "\n" + "".join(x + "\n" for x in b) + "!\n"
        return s

    def send_command(self, cmd, **kw):
        if "running-config" in cmd:
            return self.render()
        if "mypubkey" in cmd:
            return self.keys or "% No Signature RSA Keys found in configuration."
        return ""

    def send_command_timing(self, cmd, **kw):
        if cmd.startswith("crypto key generate rsa"):
            self.keys = "Key name: x\n Key Data:\n  30820122 300D0609 2A864886\n"
        return "[OK]"

    def send_config_set(self, cmds, **kw):
        ctx = None
        for c in cmds:
            if re.match(r"(interface|line|ip access-list) ", c):
                ctx = c
                self.blk.setdefault(c, [])
            elif ctx and c.startswith(self.NESTED):
                key = " ".join(c.split()[:2]) if c.startswith("transport") else c.split()[0]
                if not c.startswith(("permit", "deny", "no ")):
                    self.blk[ctx] = [x for x in self.blk[ctx] if not x.strip().startswith(key)]
                if " " + c not in self.blk[ctx]:
                    self.blk[ctx].append(" " + c)
            else:
                ctx = None
                self._glob(c)
        return ""

    def _glob(self, c):
        if c.startswith("no "):
            pos = c[3:]
            n = len(self.glob)
            self.glob = [g for g in self.glob if not g.startswith(pos)]
            if len(self.glob) == n:
                self.glob.append(c)
        else:
            for pre in self.REPLACE:
                if c.startswith(pre):
                    self.glob = [g for g in self.glob if not g.startswith(pre)]
            self.glob = [g for g in self.glob if g != "no " + c]
            if c not in self.glob:
                self.glob.append(c)


class FakeForti:
    def __init__(self):
        self.g = {"admin-telnet": "enable", "admintimeout": "10", "admin-lockout-threshold": "5",
                  "admin-lockout-duration": "60", "pre-login-banner": "disable", "post-login-banner": "disable",
                  "strong-crypto": "enable", "admin-https-ssl-versions": "tlsv1-1 tlsv1-2 tlsv1-3", "admin-ssh-v1": "disable"}
        self.pw = {"status": "disable", "minimum-length": "8"}
        self.sys, self.ntp = {"status": "disable"}, {"ntpsync": "disable"}
        self.snmp = ["1"]
        self.admins = {"admin": {}}
        self.ifaces = {"port1": {"role": "wan", "allowaccess": "ping https ssh http telnet"}}

    def disconnect(self): pass

    @staticmethod
    def kv(d):
        return "\n".join("%s : %s" % kv for kv in d.items())

    def send_command(self, cmd, **kw):
        m = {"get system global": lambda: self.kv(self.g), "get system password-policy": lambda: self.kv(self.pw),
             "get log syslogd setting": lambda: self.kv(self.sys), "get system ntp": lambda: self.kv(self.ntp)}
        if cmd in m:
            return m[cmd]()
        if cmd == "show system snmp community":
            return "".join('    edit %s\n    next\n' % i for i in self.snmp)
        if cmd == "show system admin":
            return "config system admin\n" + "".join(
                '    edit "%s"\n        set accprofile "super_admin"\n%s    next\n' % (
                    n, "".join("        set %s %s\n" % kv for kv in a.items())) for n, a in self.admins.items()) + "end"
        if cmd == "show system interface":
            return "config system interface\n" + "".join(
                '    edit "%s"\n%s    next\n' % (n, "".join("        set %s %s\n" % kv for kv in a.items()))
                for n, a in self.ifaces.items()) + "end"
        return "fake full config"

    def send_config_set(self, cmds, **kw):
        path = []
        for c in cmds:
            c = c.strip()
            if c.startswith("config "):
                path.append(c[7:])
            elif c.startswith("edit "):
                path.append("edit:" + c[5:].strip('"'))
            elif c in ("next", "end"):
                path.pop()
            elif c.startswith("set ") and "ntpserver" not in path:
                _, k, v = c.split(" ", 2)
                tgt = {"system global": self.g, "system password-policy": self.pw,
                       "log syslogd setting": self.sys, "system ntp": self.ntp}.get(path[0] if path else "")
                if path and path[0] == "system admin":
                    tgt = self.admins[path[1][5:]]
                if tgt is not None:
                    tgt[k] = v
        return ""


SELF_CISCO_R1 = """hostname R1
enable password cisco
ip http server
snmp-server community public RO
username admin privilege 15 password 0 cisco
username auditor privilege 15 secret 5 $1$abcd$xxxx
!
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
!
line con 0
 exec-timeout 0 0
 logging synchronous
line vty 0 4
 password cisco
 login
 transport input all
"""
SELF_CISCO_SW = SELF_CISCO_R1.replace("hostname R1", "hostname Switch").replace(
    "GigabitEthernet0/0", "Vlan1").replace(" ip address 10.0.0.1", " ip address 10.0.0.2")

SELF_INVENTORY = {
    "params": {"audit_server_ip": "10.0.0.100", "syslog_host": "10.0.0.100", "ntp_server": "10.0.0.100",
               "domain_name": "lab.local", "mgmt_permit": ["10.0.0.0 0.0.0.255"],
               "fortigate_trusthost": "10.0.0.0/24", "enable_secret_env": "SELFTEST_ENABLE"},
    "devices": [
        {"name": "R1", "role": "router", "platform": "cisco_ios", "host": "10.0.0.1", "username": "auditor"},
        {"name": "SW1", "role": "switch", "platform": "cisco_ios", "host": "10.0.0.2", "username": "auditor"},
        {"name": "FW", "role": "firewall", "platform": "fortigate", "host": "10.0.0.3", "username": "admin"}]}


def selftest():
    os.environ["SELFTEST_ENABLE"] = "S3lfT3st!"
    fakes = {"R1": FakeCisco(SELF_CISCO_R1), "SW1": FakeCisco(SELF_CISCO_SW), "FW": FakeForti()}
    factory = lambda dev: fakes[dev["name"]]
    outdir = tempfile.mkdtemp(prefix="selftest_")
    inv = SELF_INVENTORY
    rep = {"mode": "apply", "dry_run": False, "timestamp": "selftest", "devices": [
        process_device(d, inv["params"], "apply", False, None, factory, outdir) for d in inv["devices"]]}
    print_summary(rep)
    manual = {c.id for c in CONTROLS if c.fix is None}
    problems = []
    for d in rep["devices"]:
        for c in d["controls"]:
            if c["after"][0] != "PASS" and c["id"] not in manual:
                problems.append("%s %s -> %s %s (%s)" % (d["name"], c["id"], c["after"], c["fix_status"], c["output"]))
    html_path, json_path = write_reports(rep, outdir)
    print("\nInformes de prueba:", html_path)
    if problems:
        print("\nSELFTEST FALLÓ:\n  " + "\n  ".join(problems))
        return 1
    print("\nSELFTEST OK: todos los controles automáticos quedaron en PASS; solo restan los manuales:", sorted(manual))
    return 0


# --------------------------------------------------------------------------- #
#  CLI
# --------------------------------------------------------------------------- #
def export_controls_md():
    print("| ID | Plataforma | Ref. CIS | Control | Sev. | Remediación | Tipo |")
    print("|---|---|---|---|---|---|---|")
    for c in CONTROLS:
        print("| %s | %s | %s | %s | %s | `%s` | %s |" % (
            c.id, c.platform, c.ref, c.title, c.sev, c.fixdoc.replace("|", "\\|"),
            "Manual" if c.fix is None else "Automática"))


def main():
    ap = argparse.ArgumentParser(description="Auditoría y hardening CIS (Cisco IOS / FortiGate)")
    ap.add_argument("-i", "--inventory", default="inventory.json")
    ap.add_argument("-m", "--mode", choices=["audit", "apply"], default="audit",
                    help="audit = solo informe (default) | apply = aplica reglas + informe póstumo")
    ap.add_argument("-d", "--devices", help="Nombres separados por coma (default: todos)")
    ap.add_argument("-c", "--controls", help="IDs de controles separados por coma (default: todos)")
    ap.add_argument("--dry-run", action="store_true", help="Con -m apply: muestra comandos sin enviarlos")
    ap.add_argument("-y", "--yes", action="store_true", help="No pedir confirmación en modo apply")
    ap.add_argument("-o", "--out", default="reports")
    ap.add_argument("--selftest", action="store_true", help="Prueba el motor con equipos simulados")
    ap.add_argument("--export-controls-md", action="store_true")
    a = ap.parse_args()

    if a.export_controls_md:
        return export_controls_md() or 0
    if a.selftest:
        return selftest()

    inv = json.loads(Path(a.inventory).read_text(encoding="utf-8"))
    devs = inv["devices"]
    if a.devices:
        want = set(a.devices.split(","))
        devs = [d for d in devs if d["name"] in want]
    if not devs:
        sys.exit("Ningún dispositivo seleccionado.")
    selected = set(a.controls.split(",")) if a.controls else None

    if a.mode == "apply" and not a.dry_run and not a.yes:
        print("MODO APLICAR sobre: %s" % ", ".join(d["name"] for d in devs))
        print("Se respaldará la configuración antes de cambiar. Escriba APLICAR para continuar:")
        if input("> ").strip() != "APLICAR":
            sys.exit("Cancelado.")

    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    outdir = Path(a.out) / ("%s_%s" % (ts, a.mode))
    results = []
    for d in devs:
        print(">> %s (%s) ..." % (d["name"], d["host"]), flush=True)
        try:
            results.append(process_device(d, inv.get("params", {}), a.mode, a.dry_run, selected, real_connect, outdir))
        except Exception as e:
            print("   ERROR en %s: %s" % (d["name"], e))
    report = {"mode": a.mode, "dry_run": a.dry_run, "timestamp": ts, "devices": results}
    html_path, json_path = write_reports(report, outdir)
    print()
    print_summary(report)
    print("\nInforme HTML: %s\nInforme JSON: %s" % (html_path, json_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
