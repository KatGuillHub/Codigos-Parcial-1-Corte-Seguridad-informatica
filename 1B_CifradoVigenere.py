# Taller de Criptografía - Primer punto b) Cifrado Vigenère
# Autores: Guillermo Campo y Daniel Zambrano
# Universidad Militar Nueva Granada

'''
¿Qué es el Cifrado Vigenère?
 - Es un cifrado polialfabético: cada letra se cifra con un desplazamiento
   distinto, definido por las letras de una clave alfabética repetida.
 - Ejemplo: Texto = "ATAQUE", Clave = "LEMON"
       A + L = L
       T + E = X
       A + M = M
       Q + O = E
       U + N = H
       E + L = P
   → Resultado = "LXM EHP"

 ¿Por qué es más seguro que César?
 - César siempre usa el MISMO desplazamiento.
 - Vigenère aplica un desplazamiento DIFERENTE en cada posición,
   según la letra de la clave → rompe patrones repetitivos y dificulta
   el análisis de frecuencia.
'''

def preparar_clave(texto, clave):

    # Normalizamos la clave: solo letras mayúsculas, sin espacios
    clave = clave.upper().replace(" ", "")

    # Texto en mayúsculas, solo las letras (sin símbolos/espacios)
    texto_limpio = ''.join([c for c in texto.upper() if c.isalpha()])
    
    # Construir clave extendida letra por letra
    clave_extendida = ""
    for i in range(len(texto_limpio)):
        clave_extendida += clave[i % len(clave)]
    
    return clave_extendida

    """
    Prepara la clave alfabética para que coincida con la longitud
    del texto original (solo contando letras).
    
    - La clave se repite tantas veces como sea necesario.
    - Se ignoran los espacios y caracteres no alfabéticos.
    """

def cifrar_vigenere(texto, clave):
    
    clave_preparada = preparar_clave(texto, clave)
    resultado = ""
    indice_clave = 0
    
    for char in texto:
        if char.isalpha():
            # Determinar si es mayúscula o minúscula
            es_mayuscula = char.isupper()
            char_upper = char.upper()
            
            # Obtener valores numéricos (A=0, B=1, ..., Z=25)
            valor_char = ord(char_upper) - ord('A')
            valor_clave = ord(clave_preparada[indice_clave]) - ord('A')
            
            # Aplicar cifrado Vigenère
            char_cifrado_valor = (valor_char + valor_clave) % 26
            char_cifrado = chr(char_cifrado_valor + ord('A'))
            
            # Mantener el caso original
            if not es_mayuscula:
                char_cifrado = char_cifrado.lower()
            
            resultado += char_cifrado
            indice_clave += 1
        else:
            # Mantener espacios y otros caracteres
            resultado += char
    
    return resultado

    """
    Cifra un texto usando el algoritmo de Vigenère.
    
    Paso a paso:
      1) Preparar la clave extendida (longitud = letras del texto).
      2) Para cada letra:
         - Convertir letra y clave a valores numéricos (A=0, ..., Z=25).
         - Sumar ambos valores y aplicar módulo 26.
         - Convertir de nuevo a letra.
      3) Mantener mayúsculas/minúsculas del texto original.
    """

def descifrar_vigenere(texto_cifrado, clave):
    
    clave_preparada = preparar_clave(texto_cifrado, clave)
    resultado = ""
    indice_clave = 0
    
    for char in texto_cifrado:
        if char.isalpha():
            es_mayuscula = char.isupper()
            char_upper = char.upper()
            
            valor_char = ord(char_upper) - ord('A')
            valor_clave = ord(clave_preparada[indice_clave]) - ord('A')
            
            # Para descifrar restamos en lugar de sumar
            char_descifrado_valor = (valor_char - valor_clave) % 26
            char_descifrado = chr(char_descifrado_valor + ord('A'))
            
            if not es_mayuscula:
                char_descifrado = char_descifrado.lower()
            
            resultado += char_descifrado
            indice_clave += 1
        else:
            resultado += char
    
    return resultado

    """
    Descifra un texto cifrado con Vigenère.
    
    Paso a paso:
      1) Preparar la clave extendida igual que en el cifrado.
      2) Para cada letra:
         - Convertir letra y clave a valores numéricos (A=0, ..., Z=25).
         - Restar el valor de la clave al valor de la letra.
         - Aplicar módulo 26.
         - Convertir de nuevo a letra.
      3) Mantener mayúsculas/minúsculas del texto original.
    """

def mostrar_proceso_cifrado(texto, clave):

    print(f"Texto original: {texto}")
    print(f"Clave: {clave}")
    
    clave_extendida = preparar_clave(texto, clave)
    print(f"Clave extendida: {clave_extendida}")
    
    # Mostrar solo las letras y su correspondencia
    texto_letras = ''.join([c.upper() for c in texto if c.isalpha()])
    print(f"Solo letras: {texto_letras}")
    
    # Mostrar el proceso
    print("\nProceso de cifrado:")
    resultado_cifrado = ""
    for i, (letra, clave_letra) in enumerate(zip(texto_letras, clave_extendida)):
        valor_letra = ord(letra) - ord('A')
        valor_clave = ord(clave_letra) - ord('A')
        resultado_valor = (valor_letra + valor_clave) % 26
        resultado_letra = chr(resultado_valor + ord('A'))
        
        resultado_cifrado += resultado_letra
        print(f"{letra}({valor_letra}) + {clave_letra}({valor_clave}) = {resultado_letra}({resultado_valor})")
    
    return cifrar_vigenere(texto, clave)

    """
    Descifra un texto cifrado con Vigenère.
    
    Paso a paso:
      1) Preparar la clave extendida igual que en el cifrado.
      2) Para cada letra:
         - Convertir letra y clave a valores numéricos (A=0, ..., Z=25).
         - Restar el valor de la clave al valor de la letra.
         - Aplicar módulo 26.
         - Convertir de nuevo a letra.
      3) Mantener mayúsculas/minúsculas del texto original.
    """

# ============================================================
# Programa principal: Demostración
# ============================================================
if __name__ == "__main__":
    print("CIFRADO VIGENERE - TALLER DE CRIPTOGRAFIA")
    print("="*50)
    
    # Mensaje personalizado
    mensaje = "La seguridad es fundamental en la era digital"
    clave = "CRIPTOGRAFIA"
    
    print("1. DEMOSTRACION CON PROCESO DETALLADO:")
    mensaje_cifrado = mostrar_proceso_cifrado(mensaje, clave)
    
    print(f"\nTexto original: {mensaje}")
    print(f"Texto cifrado:  {mensaje_cifrado}")
    
    # Verificar descifrado
    print(f"\n2. VERIFICACION DEL DESCIFRADO:")
    mensaje_descifrado = descifrar_vigenere(mensaje_cifrado, clave)
    print(f"Descifrado: {mensaje_descifrado}")
    
    # Comparación con César
    print(f"\n3. POR QUE VIGENERE ES MAS SEGURO QUE CESAR?")
    
    # Ejemplo con texto repetitivo
    texto_repetitivo = "AAAAAAAAAA"
    print(f"Texto repetitivo: {texto_repetitivo}")
    
    # Con César (clave 3)
    cesar_result = ""
    for char in texto_repetitivo:
        cesar_result += chr((ord(char) - ord('A') + 3) % 26 + ord('A'))
    print(f"Cesar (clave 3):  {cesar_result} <- Patron visible!")
    
    # Con Vigenère
    vigenere_result = cifrar_vigenere(texto_repetitivo, clave)
    print(f"Vigenere:         {vigenere_result} <- Sin patron!")
    
    print(f"\nVigenere usa diferentes desplazamientos para cada letra,")
    print(f"lo que rompe el analisis de frecuencia simple.")