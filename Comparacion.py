import base64
from cryptography.fernet import Fernet
from PIL import Image
import numpy as np
import random

# Mensaje secreto a proteger
mensaje_secreto = "El ataque será a las 15:00 en punto"

print("=== COMPARACIÓN DE TÉCNICAS DE SEGURIDAD ===")
print(f"Mensaje original: {mensaje_secreto}\n")

# 1. CRIPTOGRAFÍA (Cifrado AES con Fernet)
print("1. CRIPTOGRAFÍA (Cifrado AES)")
# Generar clave de cifrado
clave = Fernet.generate_key()
cipher = Fernet(clave)
# Cifrar mensaje
mensaje_cifrado = cipher.encrypt(mensaje_secreto.encode())
print(f"Mensaje cifrado: {mensaje_cifrado.decode()}")
# Descifrar mensaje
mensaje_descifrado = cipher.decrypt(mensaje_cifrado).decode()
print(f"Mensaje descifrado: {mensaje_descifrado}")
print("→ Evidente que hay información cifrada pero no se puede leer sin clave\n")

# 2. ESTEGANOGRAFÍA (Ocultar en imagen LSB)
print("2. ESTEGANOGRAFÍA (Ocultar en imagen)")
def ocultar_mensaje_lsb(ruta_imagen, mensaje, ruta_salida):
    # Abrir imagen y convertir a array
    img = Image.open(ruta_imagen)
    array_img = np.array(img)
    
    # Convertir mensaje a binario
    bin_mensaje = ''.join([format(ord(c), '08b') for c in mensaje])
    bin_mensaje += '00000000'  # Marcador de fin
    
    # Ocultar en bits menos significativos
    alt, anc, canales = array_img.shape
    idx = 0
    for i in range(alt):
        for j in range(anc):
            for k in range(canales):
                if idx < len(bin_mensaje):
                    # Modificar solo el bit menos significativo
                    array_img[i][j][k] = (array_img[i][j][k] & 0xFE) | int(bin_mensaje[idx])
                    idx += 1
    
    # Guardar imagen con mensaje oculto
    img_oculta = Image.fromarray(array_img)
    img_oculta.save(ruta_salida)
    return f"Mensaje oculto en {ruta_salida}"

def extraer_mensaje_lsb(ruta_imagen):
    # Abrir imagen con mensaje oculto
    img = Image.open(ruta_imagen)
    array_img = np.array(img)
    
    # Extraer bits menos significativos
    bin_mensaje = ""
    alt, anc, canales = array_img.shape
    for i in range(alt):
        for j in range(anc):
            for k in range(canales):
                bin_mensaje += str(array_img[i][j][k] & 1)
    
    # Convertir binario a texto
    mensaje = ""
    for i in range(0, len(bin_mensaje), 8):
        byte = bin_mensaje[i:i+8]
        if byte == '00000000':  # Fin de mensaje
            break
        mensaje += chr(int(byte, 2))
    
    return mensaje

# Crear imagen de ejemplo si no existe
img_ejemplo = np.random.randint(0, 256, (50, 50, 3), dtype=np.uint8)
Image.fromarray(img_ejemplo).save("imagen_ejemplo.png")

# Ocultar y extraer mensaje
resultado_estego = ocultar_mensaje_lsb("imagen_ejemplo.png", mensaje_secreto, "imagen_oculta.png")
mensaje_extraido = extraer_mensaje_lsb("imagen_oculta.png")
print(f"{resultado_estego}")
print(f"Mensaje extraído: {mensaje_extraido}")

# 3. OFUSCACIÓN (Transformación reversible)
print("3. OFUSCACIÓN (Transformación reversible)")
def ofuscar_mensaje(mensaje):
    # Ofuscar usando base64 y rotación de caracteres
    mensaje_b64 = base64.b64encode(mensaje.encode()).decode()
    # Rotar caracteres
    mensaje_ofuscado = ''.join([chr((ord(c) + 5) % 256) for c in mensaje_b64])
    return mensaje_ofuscado

def desofuscar_mensaje(mensaje_ofuscado):
    # Revertir rotación
    mensaje_b64 = ''.join([chr((ord(c) - 5) % 256) for c in mensaje_ofuscado])
    # Decodificar base64
    mensaje = base64.b64decode(mensaje_b64.encode()).decode()
    return mensaje

mensaje_ofuscado = ofuscar_mensaje(mensaje_secreto)
mensaje_desofuscado = desofuscar_mensaje(mensaje_ofuscado)
print(f"Mensaje ofuscado: {mensaje_ofuscado}")
print(f"Mensaje desofuscado: {mensaje_desofuscado}")