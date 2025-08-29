# Taller de Criptografía - Ejercicio tecnico HTTPS
# Autores: Guillermo Campo y Daniel Zambrano
# Universidad Militar Nueva Granada

import requests
import ssl
import socket
from datetime import datetime

# ---- Configuración: cambia estos sitios si quieres probar otros ----
HTTPS_SITE = "https://www.google.com"    # Sitio con HTTPS
HTTP_SITE = "http://neverssl.com"        # Sitio que intentionally no tiene HTTPS

# ---------------------------
# Función: hacer petición HTTP/HTTPS con requests
# ---------------------------
def hacer_peticion(url, verificar_certificado=True, timeout=10):
    """
    Realiza una petición GET con 'requests'.
    - verificar_certificado: pasa verify=True/False a requests (True por defecto).
    - Devuelve diccionario con estado, tamaño, tiempo y encabezados (o error).
    """
    try:
        # requests hace la negociación TLS (si el esquema es https)
        resp = requests.get(url, timeout=timeout, verify=verificar_certificado)
        return {
            "url": url,
            "ok": True,
            "status_code": resp.status_code,
            "tamaño_bytes": len(resp.content),
            "tiempo_s": resp.elapsed.total_seconds(),
            "headers": dict(resp.headers)
        }
    except requests.exceptions.SSLError as e:
        # Error al validar certificado TLS (certificado inválido / expirado / CA no confiable)
        return {"url": url, "ok": False, "error": f"SSL Error: {e}"}
    except requests.exceptions.ConnectionError as e:
        # No se pudo establecer conexión (sitio caído, puerto cerrado, etc.)
        return {"url": url, "ok": False, "error": f"Connection Error: {e}"}
    except Exception as e:
        return {"url": url, "ok": False, "error": f"Other Error: {e}"}


# ---------------------------
# Función: obtener e inspeccionar certificado TLS del servidor
# ---------------------------
def obtener_info_certificado(hostname, port=443, timeout=5):
    """
    Conecta al servidor usando un contexto SSL que VERIFICA la cadena y el hostname.
    Si la conexión y verificación son exitosas devuelve información relevante
    del certificado (issuer, subject, notBefore, notAfter).
    Si falla la verificación, levanta excepción que capturamos más arriba.
    """
    context = ssl.create_default_context()  # contexto con CAs confiables por defecto
    # Activar la verificación de nombre de host (hostname verification)
    context.check_hostname = True
    # verify_mode ya está en CERT_REQUIRED para create_default_context()

    # Abrimos socket y envolvemos con TLS (esto realizará la validación del certificado)
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            # getpeercert devuelve un dict con campos como 'subject', 'issuer', 'notBefore', 'notAfter'
            cert = ssock.getpeercert()

            # Extraer sujeto (subject) y emisor (issuer) de forma legible
            subject = {name: value for ((name, value),) in cert.get("subject", [])} if cert.get("subject") else {}
            issuer = {name: value for ((name, value),) in cert.get("issuer", [])} if cert.get("issuer") else {}

            return {
                "subject": subject,
                "issuer": issuer,
                "notBefore": cert.get("notBefore"),  # formato típico: 'Jun 10 12:00:00 2025 GMT'
                "notAfter": cert.get("notAfter"),
                "version": cert.get("version"),
                "serialNumber": cert.get("serialNumber")
            }


# ---------------------------
# Helpers: parseo y comprobación de fechas
# ---------------------------
def dias_para_expiracion(notAfter_str):
    """
    Convierte la fecha 'notAfter' del certificado en un objeto datetime y
    devuelve cuántos días faltan para que expire. Si falla, retorna None.
    Formato esperado típico: 'Jun 10 12:00:00 2025 GMT'
    """
    try:
        exp = datetime.strptime(notAfter_str, "%b %d %H:%M:%S %Y %Z")
        delta = exp - datetime.utcnow()
        return delta.days
    except Exception:
        return None


# ---------------------------
# Programa principal: ejecutar pruebas y mostrar resultados
# ---------------------------
if __name__ == "__main__":
    print("=== PRUEBA BÁSICA DE HTTP vs HTTPS ===\n")

    # 1) Petición al sitio HTTPS (verificando certificado)
    print(f"-> Probando sitio HTTPS: {HTTPS_SITE}")
    resultado_https = hacer_peticion(HTTPS_SITE, verificar_certificado=True)
    if resultado_https["ok"]:
        print(f"  Estado: {resultado_https['status_code']}, Tiempo: {resultado_https['tiempo_s']:.3f}s, Tamaño: {resultado_https['tamaño_bytes']} bytes")
        # Mostrar algunos encabezados importantes (solo un subconjunto para claridad)
        headers = resultado_https["headers"]
        for h in ["Strict-Transport-Security", "Content-Security-Policy", "Server", "Date"]:
            if h in headers:
                print(f"  Header: {h}: {headers[h]}")
    else:
        print(f"  ERROR al acceder (HTTPS): {resultado_https.get('error')}")

    # Obtener y verificar certificado TLS (hostname verificable)
    try:
        host = HTTPS_SITE.split("://", 1)[1].split("/", 1)[0]  # extraer hostname
        cert_info = obtener_info_certificado(host)
        print("\n  Información del certificado TLS (verificado por el contexto SSL):")
        print(f"    Sujeto: {cert_info.get('subject')}")
        print(f"    Emisor: {cert_info.get('issuer')}")
        print(f"    Válido desde: {cert_info.get('notBefore')}")
        print(f"    Válido hasta: {cert_info.get('notAfter')}")
        dias = dias_para_expiracion(cert_info.get("notAfter"))
        if dias is not None:
            print(f"    Días hasta expiración: {dias} días")
        else:
            print("    No se pudo calcular días hasta expiración (formato inesperado)")
    except ssl.SSLError as e:
        print(f"\n  ERROR de verificación TLS: {e} (certificado inválido o cadena no confiable)")
    except Exception as e:
        print(f"\n  No se pudo obtener/validar certificado: {e}")

    print("\n" + "-"*60 + "\n")

    # 2) Petición al sitio HTTP (sin TLS)
    print(f"-> Probando sitio HTTP (sin TLS): {HTTP_SITE}")
    resultado_http = hacer_peticion(HTTP_SITE, verificar_certificado=False)
    if resultado_http["ok"]:
        print(f"  Estado: {resultado_http['status_code']}, Tiempo: {resultado_http['tiempo_s']:.3f}s, Tamaño: {resultado_http['tamaño_bytes']} bytes")
        # Mostrar algunos encabezados
        headers = resultado_http["headers"]
        for h in ["Server", "Date", "Content-Type"]:
            if h in headers:
                print(f"  Header: {h}: {headers[h]}")
        print("  Nota: comunicación NO cifrada (HTTP). Los datos viajan en texto claro.")
    else:
        print(f"  ERROR al acceder (HTTP): {resultado_http.get('error')}")

    print("\n=== Resumen y observaciones breves ===\n")
    print("1) Diferencias observadas:")
    print("   - HTTPS: conexión cifrada. El cliente (requests / ssl context) valida el certificado del servidor.")
    print("   - HTTP: comunicación en claro (sin cifrado), por lo que no hay certificado TLS que verificar.")
    print("2) Encabezados importantes (ej.: HSTS, CSP) solo aplican sobre HTTPS y ayudan a endurecer seguridad.")
    print("3) Verificación de certificado (cómo se comprueba):")
    print("   - El cliente valida la cadena de confianza (CA) y que el nombre del sitio coincida con el certificado.")
    print("   - También se verifica que la fecha actual esté entre 'notBefore' y 'notAfter'.")
    print("   - En este script hemos intentado ambas comprobaciones: 1) requests con verify=True y 2) ssl context con check_hostname=True.")
    print("\nFin de la prueba. Si quieres que guarde resultados en JSON o que pruebe otros dominios, lo adapto.")
