# Taller de Criptografía - Sexto punto, Blockchain Básico
# Autores: Guillermo Campo y Daniel Zambrano
# Universidad Militar Nueva Granada

import hashlib
from datetime import datetime

class Bloque:
    def __init__(self, indice, datos, hash_anterior):
        """
        Representa un bloque dentro de la blockchain.
        Cada bloque contiene:
        - índice: posición en la cadena
        - timestamp: fecha y hora exacta de creación
        - datos: información guardada en el bloque (transacción, registro, etc.)
        - hash_anterior: asegura el enlace con el bloque previo
        - hash: identificador único calculado con SHA-256
        """
        self.indice = indice
        self.timestamp = datetime.now().isoformat()
        self.datos = datos
        self.hash_anterior = hash_anterior
        self.hash = self.calcular_hash()  # se calcula automáticamente al crear el bloque
    
    def calcular_hash(self):
        """
        Genera el hash SHA-256 del bloque a partir de todos sus campos.
        Este hash garantiza la inmutabilidad: 
        cualquier cambio en los datos alterará el hash.
        """
        contenido = (
            str(self.indice) +
            self.timestamp +
            str(self.datos) +
            self.hash_anterior
        )
        return hashlib.sha256(contenido.encode()).hexdigest()

class Blockchain:
    def __init__(self):
        """ Inicializa la blockchain con un único bloque: el bloque génesis """
        self.cadena = [self.crear_bloque_genesis()]
    
    def crear_bloque_genesis(self):
        """
        Crea el primer bloque de la cadena (bloque génesis).
        Se define manualmente y no tiene un bloque previo (hash_anterior = "0").
        """
        return Bloque(0, "Bloque Génesis - Universidad Militar Nueva Granada", "0")
    
    def obtener_ultimo_bloque(self):
        """ Devuelve el último bloque agregado a la cadena """
        return self.cadena[-1]
    
    def agregar_bloque(self, datos):
        """
        Crea un nuevo bloque con los datos recibidos y lo enlaza
        al último bloque de la cadena usando el hash del bloque previo.
        """
        ultimo = self.obtener_ultimo_bloque()
        nuevo_indice = ultimo.indice + 1
        nuevo = Bloque(nuevo_indice, datos, ultimo.hash)
        self.cadena.append(nuevo)
        return nuevo
    
    def es_cadena_valida(self):
        """
        Verifica la integridad de toda la blockchain.
        Revisa dos condiciones:
        1. Que el hash guardado coincida con el hash recalculado.
        2. Que el hash_anterior de cada bloque coincida con el hash real del bloque previo.
        Si alguna falla, significa que la cadena fue alterada.
        """
        for i in range(1, len(self.cadena)):
            actual = self.cadena[i]
            anterior = self.cadena[i-1]
            if actual.hash != actual.calcular_hash():
                return False
            if actual.hash_anterior != anterior.hash:
                return False
        return True

# ===============================
# PROGRAMA PRINCIPAL
# ===============================
if __name__ == "__main__":
    print("SIMULACIÓN BÁSICA DE BLOCKCHAIN")
    print("="*40)
    
    # 1. Crear la blockchain
    mi_blockchain = Blockchain()

    # 2. Agregar algunos bloques con datos ficticios
    datos = [
        "Transacción: Guillermo envía 10 monedas a Daniel",
        "Transacción: Daniel paga 5 monedas a la Universidad",
        "Registro: Certificado de curso de Criptografía"
    ]

    for d in datos:
        bloque = mi_blockchain.agregar_bloque(d)
        print(f"Bloque {bloque.indice} agregado - Hash: {bloque.hash[:20]}...")
    
    # 3. Verificar integridad original (debe ser True)
    print("\n¿Cadena válida?", mi_blockchain.es_cadena_valida())

    # 4. Simular ataque: modificar datos de un bloque intermedio
    print("\n🚨 Modificando datos en el bloque 1...")
    mi_blockchain.cadena[1].datos = "Transacción FALSA: Guillermo recibe 1000 monedas"
    
    # 5. Verificar integridad después del ataque (debe ser False)
    print("¿Cadena válida después de la modificación?", mi_blockchain.es_cadena_valida())
