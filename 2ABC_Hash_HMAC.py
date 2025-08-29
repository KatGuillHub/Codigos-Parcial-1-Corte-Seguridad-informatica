# Taller de Criptografía - Segundo pumto, Funciones Hash y HMAC
# Autores: Guillermo Campo y Daniel Zambrano
# Universidad Militar Nueva Granada

import hashlib
import hmac

'''
Este programa implementa:
   1. Uso de hashlib para calcular el hash SHA-256 de textos y archivos,
      mostrando cómo cambia el valor al modificar el contenido.
   2. Comparación de hashes de dos archivos para verificar su integridad.
   3. Generación y verificación de HMAC utilizando SHA-256 y una clave secreta.

 Con este código demostramos cómo los algoritmos de hash y HMAC se aplican
 en la seguridad informática para garantizar integridad y autenticación.
'''

# --- 1. Hash de textos y archivos ---
def hash_sha256(data):
    """Devuelve el hash SHA-256 de un texto o bytes"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()

    '''
    Calcula el hash SHA-256 de un texto o datos en bytes.

    Parámetro:
        data (str o bytes): mensaje de entrada.
    Retorna un str hash en representación hexadecimal de 64 caracteres.
    '''

def hash_archivo(ruta):
    """Devuelve el hash SHA-256 de un archivo"""
    h = hashlib.sha256()
    with open(ruta, 'rb') as f:
        for bloque in iter(lambda: f.read(4096), b""):
            h.update(bloque)
    return h.hexdigest()

    '''
    Calcula el hash SHA-256 de un archivo.

    Parámetro:
        ruta (str): ruta al archivo a procesar.
    Retorna un str: hash SHA-256 del archivo en hexadecimal.
    
    * Se procesa el archivo en bloques (4096 bytes) para soportar
    archivos grandes sin problemas de memoria.
    '''


# --- 2. Comparación de hashes de archivos ---
def archivos_identicos(archivo1, archivo2):
    """Compara dos archivos por su hash SHA-256"""
    return hash_archivo(archivo1) == hash_archivo(archivo2)

    '''
    Compara dos archivos verificando si sus hashes SHA-256 son iguales.

    Parámetros:
        archivo1 (str): ruta al primer archivo.
        archivo2 (str): ruta al segundo archivo.
    Retorna:
        bool: True si son idénticos, False si difieren.
    
    Aplicación:
        Permite verificar la integridad de descargas o copias de archivos.
    '''


# --- 3. Generación y verificación de HMAC ---
def generar_hmac(mensaje, clave):
    """Genera HMAC-SHA256 de un mensaje con clave"""
    if isinstance(mensaje, str):
        mensaje = mensaje.encode('utf-8')
    if isinstance(clave, str):
        clave = clave.encode('utf-8')
    return hmac.new(clave, mensaje, hashlib.sha256).hexdigest()

    '''
    Genera un código HMAC utilizando SHA-256.

    Parámetros:
        mensaje (str o bytes): mensaje original.
        clave (str o bytes): clave secreta compartida.
    Retorna:
        str: HMAC en formato hexadecimal.

    Nota:
        A diferencia de un hash normal, el HMAC incluye una clave secreta,
        por lo que solo quien conoce la clave puede generar/verificarlo.
    '''

def verificar_hmac(mensaje, clave, hmac_esperado):
    """Verifica si el HMAC calculado coincide con el esperado"""
    hmac_calc = generar_hmac(mensaje, clave)
    return hmac.compare_digest(hmac_calc, hmac_esperado)

    '''
    Verifica si el HMAC calculado coincide con el esperado.

    Parámetros:
        mensaje (str): mensaje recibido.
        clave (str): clave secreta compartida.
        hmac_esperado (str): HMAC que se espera validar.
    Retorna:
        bool: True si el HMAC coincide, False en caso contrario.

    Aplicación:
        Garantiza autenticidad (quién lo envió) e integridad (que no fue alterado).
    '''


# ============================================================
# Programa principal: Demostración
# ============================================================
if __name__ == "__main__":
    # 1. Hash de textos
    texto = "Guillermo Campo y Daniel Zambrano"
    print("Hash original:", hash_sha256(texto))
    print("Hash modificado:", hash_sha256(texto + "modificacion de prueba"))

    # 2. Comparar archivos
    # Creamos tres archivos simples: dos idénticos y uno alterado
    with open("a.txt", "w") as f: f.write("contenido")
    with open("b.txt", "w") as f: f.write("contenido")
    with open("c.txt", "w") as f: f.write("contenido modificado")

    # Comparación de archivos (deben coincidir los hashes de a.txt y b.txt)
    print("\nArchivos a.txt y b.txt identicos?:", archivos_identicos("a.txt", "b.txt"))
    print("Archivos a.txt y c.txt identicos?:", archivos_identicos("a.txt", "c.txt"))

    # 3. HMAC
    clave = "clave_secreta"
    msg = "Transferir $1000"
    h = generar_hmac(msg, clave)
    print("\nHMAC generado:", h)
    print("Verificacion correcta?:", verificar_hmac(msg, clave, h))
    print("Verificacion con mensaje modificado?:", verificar_hmac("Transferir $2000", clave, h))
