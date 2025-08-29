# Taller de Criptografía - Primer punto a) Cifrado César
# Autores: Guillermo Campo y Daniel Zambrano
# Universidad Militar Nueva Granada

'''
¿Qué es el Cifrado César?
 - Es un cifrado por sustitución monoalfabético: cada letra se reemplaza
   por otra que está "k" posiciones más adelante en el alfabeto (clave = k).
 - Matemáticamente: si cada letra se mapea a un índice 0..25, entonces:
       E_k(i) = (i + k) mod 26      # Cifrado
       D_k(j) = (j - k) mod 26      # Descifrado
 - Solo afecta letras; todo lo demás (espacios, signos) se deja igual.

 - Opera sobre el alfabeto inglés (A-Z, a-z). Letras con tilde o 'ñ' NO se
   desplazan correctamente si entran al algoritmo, porque usamos offsets ASCII
   (ord('A') y ord('a')) y módulo 26. Por eso, el código decide:
   * Si "es letra" (isalpha) → intenta desplazarla asumiendo A-Z o a-z.
   * Si no es letra (o no está en A-Z/a-z) → la deja igual.
'''

def cifrar_cesar(texto, clave):

    resultado = ""
    
    # Recorremos cada carácter del texto
    for char in texto:
        # Solo procesamos letras del alfabeto
        if char.isalpha():
            # Determinar si la letra es mayúscula o minúscula
            ascii_offset = ord('A') if char.isupper() else ord('a')
            
            # Aplicar la fórmula del desplazamiento (con módulo 26 para "circular" en el alfabeto)
            char_cifrado = chr((ord(char) - ascii_offset + clave) % 26 + ascii_offset)
            resultado += char_cifrado
        else:
            # Si es un espacio, número o símbolo, se deja igual
            resultado += char
    
    return resultado

    """
    Cifra un texto usando el algoritmo clásico de Cifrado César.

    Parámetros:
        texto (str): Mensaje original a cifrar.
        clave (int): Desplazamiento. Puede ser positivo, negativo o mayor a 26.
                     El uso de '% 26' asegura que cualquier clave sea equivalente
                     a una dentro del rango [0, 25].

    Retorna:
        str: Mensaje cifrado.

    Idea central del algoritmo (por carácter 'char'):
      1) Verificar si 'char' es una letra.
      2) Convertir 'char' a un índice 0..25 relativo a 'A' o a 'a' (según su caso).
         - ascii_offset = ord('A') si es mayúscula, o ord('a') si es minúscula.
         - índice = ord(char) - ascii_offset
      3) Aplicar el desplazamiento con módulo 26:
         - índice_cifrado = (índice + clave) % 26
         Esto hace que, por ejemplo, con clave 3:
             'X'(23) → (23+3) % 26 = 0 → 'A'
      4) Reconstruir el carácter cifrado:
         - char_cifrado = chr(índice_cifrado + ascii_offset)
      5) Si no es letra, se agrega tal cual al resultado.
    """

def descifrar_cesar(texto_cifrado, clave):
   
    return cifrar_cesar(texto_cifrado, -clave)

    """
        Descifra un texto cifrado con César usando la MISMA rutina de cifrado
        pero con la clave en negativo.

        Por qué funciona:
        - Si cifrar es sumar 'k' (mod 26), descifrar es restar 'k' (mod 26).
        - Usar 'cifrar_cesar' con '-clave' implementa exactamente eso.

        Parámetros:
            texto_cifrado (str): Mensaje encriptado con César.
            clave (int): Clave original usada para cifrar.

        Retorna un str que es el mensaje descifrado.
    """

def ataque_fuerza_bruta(texto_cifrado):

    print(f"Texto cifrado: {texto_cifrado}")
    print("\nPosibles descifraciones:")
    
     # Prueba con todas las claves posibles en el alfabeto (26 letras)
    for clave in range(26):
        descifrado = descifrar_cesar(texto_cifrado, clave)
        print(f"Clave {clave:2d}: {descifrado}")
    
    """
    ¿Por qué es posible?
      - César tiene SOLO 26 claves posibles (el tamaño del alfabeto).
      - Un atacante puede probar todas (0 a 25) y revisar cuál resultado
        "tiene sentido" en el idioma del mensaje.

    Qué hace:
      - Intenta descifrar 'texto_cifrado' con TODAS las claves posibles.
      - Imprime cada hipótesis de descifrado junto con la clave probada.

    Complejidad:
      - O(26 * n), donde n es la longitud del texto.
    """

# ============================================================
# Programa principal: Pruebas de cifrado y descifrado
# ============================================================
if __name__ == "__main__":
    print("CIFRADO CESAR - TALLER DE CRIPTOGRAFIA")
    
    # -------------------------
    # Prueba 1: Cifrar nombres
    # -------------------------
    nombres = ["Guillermo Campo", "Daniel Zambrano"]
    clave = 5
    
    print(f"\n1. CIFRANDO NOMBRES CON CLAVE {clave}:")
    for nombre in nombres:
        nombre_cifrado = cifrar_cesar(nombre, clave)
        nombre_descifrado = descifrar_cesar(nombre_cifrado, clave)
        print(f"Original:    {nombre}")
        print(f"Cifrado:     {nombre_cifrado}")
        print(f"Descifrado:  {nombre_descifrado}")
        print(" ")

    # -------------------------
    # Prueba 2: Cifrar una frase
    # -------------------------
    frase = "La criptografia es fascinante"
    clave_frase = 13
    
    print(f"\n2. CIFRANDO FRASE CON CLAVE {clave_frase}:")
    frase_cifrada = cifrar_cesar(frase, clave_frase)
    print(f"Original:  {frase}")
    print(f"Cifrada:   {frase_cifrada}")
    

    # -------------------------
    # Prueba 3: Ataque de fuerza bruta
    # -------------------------
    # Mensaje cifrado con clave 3
    print(f"\n3. ATAQUE DE FUERZA BRUTA:")
    mensaje_secreto = "PYNIR RF VZCBEGNAGR"  # Texto original: "CLAVE ES IMPORTANTE"
    ataque_fuerza_bruta(mensaje_secreto)
    
    # Verificación con la clave correcta
    print(f"\nEl mensaje secreto dice: {descifrar_cesar(mensaje_secreto, 13)}!")