# Taller de Criptografía - Primer punto c Cifrado Simétrico Moderno Fernet
# Autores: Guillermo Campo y Daniel Zambrano
# Universidad Militar Nueva Granada

from cryptography.fernet import Fernet

'''
 CIFRADO SIMÉTRICO MODERNO CON FERNET (AES + HMAC)
 ================================================================
 Fernet es una implementación de cifrado simétrico incluida en
 la librería "cryptography". Internamente combina:
   - AES en modo CBC (para confidencialidad de los datos).
   - HMAC con SHA256 (para garantizar integridad y autenticidad).

 Con esto, cada mensaje cifrado incluye:
   1. Una clave de sesión única (IV/nonce).
   2. El texto cifrado (AES).
   3. Un tag de verificación (HMAC).

 Así se asegura que:
   - Solo quien tenga la clave pueda leer el mensaje (confidencialidad).
   - No se pueda alterar el mensaje sin ser detectado (integridad).
================================================================
'''

# --- 1. Generar una clave secreta ---
'''
Esta clave debe mantenerse privada, ya que con ella se puede cifrar y descifrar.
'''
clave = Fernet.generate_key()
fernet = Fernet(clave)
print(f"Clave generada: {clave.decode()}")

# --- 2. Definir un mensaje secreto ---
'''
Este es el texto en claro que deseamos proteger.
'''
mensaje_original = "Este es un mensaje confidencial de Guillermo y Daniel"
print(f"\nMensaje original: {mensaje_original}")

# --- 3. Cifrar el mensaje ---
'''
El método encrypt() recibe los datos en bytes.
Se codifica el mensaje a UTF-8, se cifra con AES-CBC y se añade
automáticamente un tag de autenticación con HMAC.
'''
mensaje_cifrado = fernet.encrypt(mensaje_original.encode())
print(f"Mensaje cifrado: {mensaje_cifrado}")

# --- 4. Descifrar el mensaje ---
'''
El método decrypt() recibe los datos cifrados y:
   1. Verifica que no hayan sido alterados (HMAC).
   2. Descifra con la clave AES correspondiente.
Finalmente convertimos de bytes a string (UTF-8).
'''
mensaje_descifrado = fernet.decrypt(mensaje_cifrado).decode()
print(f"Mensaje descifrado: {mensaje_descifrado}")

# --- 5. Cifrado y descifrado de un archivo ---
'''
A continuación se aplica el mismo procedimiento pero sobre
un archivo completo en lugar de un mensaje de texto.
'''
# Crear archivo de prueba
with open("secreto.txt", "w", encoding="utf-8") as f:
    f.write("Este archivo contiene información confidencial.\n")

# Leer y cifrar contenido del archivo en modo binario
with open("secreto.txt", "rb") as f:
    datos = f.read()
datos_cifrados = fernet.encrypt(datos)

# Guardar el archivo cifrado con extensión .encrypted
with open("secreto.encrypted", "wb") as f:
    f.write(datos_cifrados)
print("\nArchivo cifrado creado: secreto.encrypted")

# Leer archivo cifrado en modo binario y luego descifrarlo
with open("secreto.encrypted", "rb") as f:
    datos_leidos = f.read()
datos_descifrados = fernet.decrypt(datos_leidos)

# Guardar el archivo descifrado como una nueva copia
with open("secreto.decrypted.txt", "wb") as f:
    f.write(datos_descifrados)
print("Archivo descifrado creado: secreto.decrypted.txt")