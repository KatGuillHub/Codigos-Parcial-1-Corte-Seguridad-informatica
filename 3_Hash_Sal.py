# Taller de Criptografía - Tercer pumto, Hash y sal
# Autores: Guillermo Campo y Daniel Zambrano
# Universidad Militar Nueva Granada

import json
import secrets
import hashlib
import hmac
import os
from datetime import datetime
from typing import Tuple

DB_FILENAME = "usuarios_db.json"  # archivo de persistencia (solo demo)

class SistemaAutenticacion:
    """
    Sistema simple de autenticación que:
    - Registra usuarios almacenando (sal, hash) en un JSON.
    - Autentica calculando hash = PBKDF2-HMAC-SHA256(sal, contraseña, iteraciones).
    - Usa comparaciones seguras y sales únicas por usuario.
    """
    def __init__(self, db_path: str = DB_FILENAME):
        self.db_path = db_path
        # cargar usuarios desde archivo (si existe)
        self.usuarios = self._cargar_usuarios()

    # ---------- Funciones Criptográficas ----------
    def _generar_sal(self, n_bytes: int = 16) -> bytes:
        """Genera una sal criptográficamente segura (en bytes)."""
        return secrets.token_bytes(n_bytes)

    def _hash_password(self, password: str, sal: bytes, iterations: int = 100_000) -> bytes:
        """
        Deriva un hash de la contraseña usando PBKDF2-HMAC-SHA256.
        - iteraciones aumenta el costo computacional (recomendado para contraseñas).
        - Retorna bytes (no hex) para comparar/almacenar.
        """
        password_bytes = password.encode('utf-8')
        return hashlib.pbkdf2_hmac('sha256', password_bytes, sal, iterations)

    # ---------- Persistencia ----------
    def _guardar_usuarios(self) -> None:
        """Guarda la estructura self.usuarios en JSON (sales y hashes en hex)."""
        serializable = {}
        for user, datos in self.usuarios.items():
            serializable[user] = {
                'sal': datos['sal'].hex(),
                'password_hash': datos['password_hash'].hex(),
                'fecha_registro': datos['fecha_registro'],
                'intentos_fallidos': datos.get('intentos_fallidos', 0)
            }
        with open(self.db_path, 'w', encoding='utf-8') as f:
            json.dump(serializable, f, indent=2, ensure_ascii=False)

    def _cargar_usuarios(self) -> dict:
        """Carga usuarios desde JSON devolviendo la estructura en memoria (bytes para sal/hash)."""
        if not os.path.exists(self.db_path):
            return {}
        try:
            with open(self.db_path, 'r', encoding='utf-8') as f:
                raw = json.load(f)
            usuarios = {}
            for user, datos in raw.items():
                usuarios[user] = {
                    'sal': bytes.fromhex(datos['sal']),
                    'password_hash': bytes.fromhex(datos['password_hash']),
                    'fecha_registro': datos.get('fecha_registro', ''),
                    'intentos_fallidos': datos.get('intentos_fallidos', 0)
                }
            return usuarios
        except Exception:
            # Si hay error de lectura -> empezar vacio (mejor informar en prod)
            return {}

    # ---------- Operaciones principales ----------
    def registrar_usuario(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Registra un usuario:
        - Genera sal única
        - Deriva hash con PBKDF2-HMAC-SHA256
        - Almacena sal y hash (en bytes internamente)
        """
        if username in self.usuarios:
            return False, "El usuario ya existe"

        sal = self._generar_sal()
        password_hash = self._hash_password(password, sal)  # usa iteraciones por defecto
        self.usuarios[username] = {
            'sal': sal,
            'password_hash': password_hash,
            'fecha_registro': datetime.utcnow().isoformat() + "Z",
            'intentos_fallidos': 0
        }
        self._guardar_usuarios()
        return True, "Usuario registrado exitosamente"

    def iniciar_sesion(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Intenta autenticar:
        - Recupera sal almacenada
        - Calcula hash de la contraseña proporcionada con la misma sal
        - Compara con hash almacenado usando hmac.compare_digest (seguro contra timing)
        """
        usuario = self.usuarios.get(username)
        if usuario is None:
            return False, "Usuario no encontrado"

        sal = usuario['sal']
        esperado = usuario['password_hash']
        intento_hash = self._hash_password(password, sal)

        # Comparación segura
        if hmac.compare_digest(intento_hash, esperado):
            usuario['intentos_fallidos'] = 0
            self._guardar_usuarios()
            return True, "Inicio de sesion exitoso"
        else:
            usuario['intentos_fallidos'] = usuario.get('intentos_fallidos', 0) + 1
            self._guardar_usuarios()
            return False, f"Contrasena incorrecta (intento {usuario['intentos_fallidos']})"

    def mostrar_usuario(self, username: str) -> dict:
        """Devuelve información no sensible del usuario para demostración (sal y hash truncados)."""
        u = self.usuarios.get(username)
        if not u:
            return {}
        return {
            'username': username,
            'sal_trunc': u['sal'].hex()[:16] + "...",
            'hash_trunc': u['password_hash'].hex()[:16] + "...",
            'fecha_registro': u['fecha_registro'],
            'intentos_fallidos': u.get('intentos_fallidos', 0)
        }


# ============================================================
# Programa principal: Demostración
# ============================================================
if __name__ == "__main__":

    print("AUTENTICACION CON HASH Y SAL")
    sistema = SistemaAutenticacion()

    # Registrar 3 usuarios de prueba (uno con contraseña débil a modo demostración)
    pruebas = [("guillermo", "MiClave123!"), ("daniel", "1202232"), ("admin", "admin")]
    for user, pwd in pruebas:
        ok, msg = sistema.registrar_usuario(user, pwd)
        print(f"Registrar {user}: {msg}")
        if ok:
            print("  >", sistema.mostrar_usuario(user))

    # Intentos de login correctos e incorrectos
    print("\nIntentos de inicio de sesion:")
    for user, pwd in pruebas:
        ok, msg = sistema.iniciar_sesion(user, pwd)
        print(f"Login {user} (correcto): {msg}")

    malos = [("guillermo", "ClaveIncorrecta"), ("daniel", "123456"), ("admin", "password")]
    for user, pwd in malos:
        ok, msg = sistema.iniciar_sesion(user, pwd)
        print(f"Login {user} (incorrecto): {msg}")

    # Limpieza (archivo temporario)
    try:
        os.remove(DB_FILENAME)
    except Exception:
        pass