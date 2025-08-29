# Taller de Criptografía - Quinto punto, Firma Digital con RSA
# Autores: Guillermo Campo y Daniel Zambrano
# Universidad Militar Nueva Granada

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

# ==============================
# 1. GENERACIÓN DE PAR DE CLAVES
# ==============================

# Se genera una clave privada RSA de 2048 bits
clave_privada = rsa.generate_private_key(
    public_exponent=65537,   # Exponente público estándar
    key_size=2048            # Longitud de clave (segura y comúnmente usada)
)

# A partir de la privada, se deriva la clave pública
clave_publica = clave_privada.public_key()

print("Par de claves RSA generado exitosamente")

# ==============================
# 2. FIRMA DE UN MENSAJE
# ==============================

mensaje = "Este es un mensaje importante para firmar."
print(f"\nMensaje original:\n{mensaje}")

# La firma se genera con la clave privada usando PSS + SHA-256
firma = clave_privada.sign(
    mensaje.encode(),  # Convertimos el mensaje a bytes
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),   # Generador de máscara
        salt_length=padding.PSS.MAX_LENGTH   # Longitud máxima de sal
    ),
    hashes.SHA256()  # Algoritmo de hash
)

print(f"Mensaje firmado")
print(f"Firma (bytes): {firma[:20]}... ({len(firma)} bytes)")

# ==============================
# 3. VERIFICACIÓN DE LA FIRMA
# ==============================

try:
    clave_publica.verify(
        firma,
        mensaje.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Verificacion exitosa: La firma es VALIDA")
except InvalidSignature:
    print("La firma es INVALIDA")

# ==============================
# 4. PRUEBA CON MENSAJE ALTERADO
# ==============================

mensaje_modificado = mensaje.replace("importante", "alterado")
print(f"\nMensaje modificado:\n{mensaje_modificado}")

# Intentamos verificar la firma original con el mensaje cambiado
try:
    clave_publica.verify(
        firma,
        mensaje_modificado.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("ERROR: La firma fue aceptada para un mensaje alterado")
except InvalidSignature:
    print("Correcto: La firma NO es valida si el mensaje fue modificado")