import os
import json
import time
import hmac
import hashlib
import base64
import tempfile
import glob
import random
import re
from datetime import datetime, timezone
from abc import ABC, abstractmethod

try:
    import requests
except ImportError:
    raise ImportError("CrafyCAPTCHA requiere 'requests'. Instálalo con: pip install requests")

try:
    import nacl.bindings
    import nacl.hash
    import nacl.encoding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
except ImportError:
    raise ImportError("CrafyCAPTCHA requiere librerías criptográficas. Instálalas con: pip install pynacl cryptography")


class _Cryptor:
    """
    Clase interna que encapsula la lógica criptográfica.
    """
    ENCRYPTION_ALGORITHM = 'AES-256-CBC'
    HASHING_ALGORITHM = 'sha256'

    # Constantes Sodium
    SALT_LEN = 16
    KEY_LEN = 32
    NONCE_LEN = 24

    def __init__(self, secret: str):
        if not secret:
            raise ValueError("Secret no puede ser vacío.")
        self.secret = secret.encode('utf-8')
        
        # Derivación de llaves pre-calculadas (BLAKE2b y SHA256)
        self.v3_key = nacl.hash.generichash(
            self.secret, 
            digest_size=self.KEY_LEN, 
            encoder=nacl.encoding.RawEncoder
        )
        self.v1_key = hashlib.sha256(self.secret).digest()

    def encrypt(self, plaintext: str, version: int = 3) -> str:
        pt_bytes = plaintext.encode('utf-8')

        if version == 3:
            nonce = os.urandom(self.NONCE_LEN)
            ciphertext = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
                pt_bytes, b'', nonce, self.v3_key
            )
            out = nonce + ciphertext
            return ';v3_;' + base64.b64encode(out).decode('utf-8')

        elif version == 2:
            salt = os.urandom(self.SALT_LEN)
            key = nacl.bindings.crypto_pwhash(
                self.KEY_LEN, self.secret, salt,
                nacl.bindings.crypto_pwhash_OPSLIMIT_INTERACTIVE,
                nacl.bindings.crypto_pwhash_MEMLIMIT_INTERACTIVE,
                nacl.bindings.crypto_pwhash_ALG_DEFAULT
            )
            nonce = os.urandom(self.NONCE_LEN)
            ciphertext = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
                pt_bytes, b'', nonce, key
            )
            out = salt + nonce + ciphertext
            return ';v2_;' + base64.b64encode(out).decode('utf-8')

        else:
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(self.v1_key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            pad_len = 16 - (len(pt_bytes) % 16)
            padded_pt = pt_bytes + bytes([pad_len] * pad_len)
            
            cipher_text = encryptor.update(padded_pt) + encryptor.finalize()
            mac = hmac.new(self.v1_key, cipher_text, hashlib.sha256).digest()
            
            return (iv + mac + cipher_text).hex()

    def decrypt(self, input_str: str) -> str:
        try:
            first_chars = input_str[:5]

            if first_chars == ';v3_;':
                decoded = base64.b64decode(input_str[5:])
                if len(decoded) < self.NONCE_LEN:
                    return None

                nonce = decoded[:self.NONCE_LEN]
                ciphertext = decoded[self.NONCE_LEN:]

                plaintext = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
                    ciphertext, b'', nonce, self.v3_key
                )
                return plaintext.decode('utf-8')

            elif first_chars == ';v2_;':
                decoded = base64.b64decode(input_str[5:])
                if len(decoded) < (self.SALT_LEN + self.NONCE_LEN + 1):
                    return None

                salt = decoded[:self.SALT_LEN]
                nonce = decoded[self.SALT_LEN : self.SALT_LEN + self.NONCE_LEN]
                ciphertext = decoded[self.SALT_LEN + self.NONCE_LEN :]

                key = nacl.bindings.crypto_pwhash(
                    self.KEY_LEN, self.secret, salt,
                    nacl.bindings.crypto_pwhash_OPSLIMIT_INTERACTIVE,
                    nacl.bindings.crypto_pwhash_MEMLIMIT_INTERACTIVE,
                    nacl.bindings.crypto_pwhash_ALG_DEFAULT
                )

                plaintext = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
                    ciphertext, b'', nonce, key
                )
                return plaintext.decode('utf-8')

            else:
                if len(input_str) % 2 != 0 or not re.match(r'^[0-9a-fA-F]+$', input_str):
                    return None

                binary_input = bytes.fromhex(input_str)
                if len(binary_input) < 48:
                    return None

                iv = binary_input[:16]
                mac = binary_input[16:48]
                cipher_text = binary_input[48:]

                calculated_mac = hmac.new(self.v1_key, cipher_text, hashlib.sha256).digest()

                if not hmac.compare_digest(mac, calculated_mac):
                    return None

                cipher = Cipher(algorithms.AES(self.v1_key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                padded_pt = decryptor.update(cipher_text) + decryptor.finalize()

                pad_len = padded_pt[-1]
                plaintext = padded_pt[:-pad_len]
                return plaintext.decode('utf-8')

        except Exception:
            return None


# ==============================================================================
# ESTRATEGIAS DE ALMACENAMIENTO (Storage Adapters)
# ==============================================================================

class StorageAdapter(ABC):
    """
    Contrato base para el almacenamiento de la Caché y los Nonces.
    """
    @abstractmethod
    def get_cache(self, key: str) -> str:
        pass

    @abstractmethod
    def set_cache(self, key: str, data: str, expires_at: int) -> None:
        pass

    @abstractmethod
    def delete_cache(self, key: str) -> None:
        pass

    @abstractmethod
    def store_nonce(self, nonce: str, expires_at: int) -> None:
        pass

    @abstractmethod
    def consume_nonce(self, nonce: str) -> bool:
        pass

    @abstractmethod
    def clear_all_nonces(self) -> int:
        pass

    @abstractmethod
    def gc_nonces(self) -> None:
        pass


class FileStorage(StorageAdapter):
    """
    Almacenamiento por defecto utilizando el sistema de archivos local.
    """
    def __init__(self, temp_dir: str):
        self.cache_dir = temp_dir
        self.nonce_dir = os.path.join(temp_dir, 'crafy_nonces')
        os.makedirs(self.nonce_dir, mode=0o777, exist_ok=True)

    def get_cache(self, key: str) -> str:
        file_path = os.path.join(self.cache_dir, f"{key}.json")
        try:
            with open(file_path, 'r') as f:
                return f.read()
        except OSError:
            return None

    def set_cache(self, key: str, data: str, expires_at: int) -> None:
        file_path = os.path.join(self.cache_dir, f"{key}.json")
        try:
            with open(file_path, 'w') as f:
                f.write(data)
            os.chmod(file_path, 0o600)
        except OSError:
            pass

    def delete_cache(self, key: str) -> None:
        file_path = os.path.join(self.cache_dir, f"{key}.json")
        try:
            os.unlink(file_path)
        except OSError:
            pass

    def store_nonce(self, nonce: str, expires_at: int) -> None:
        file_path = os.path.join(self.nonce_dir, f'nonce_{nonce}.lock')
        try:
            with open(file_path, 'w') as f:
                f.write(str(expires_at))
        except OSError:
            pass

    def consume_nonce(self, nonce: str) -> bool:
        file_path = os.path.join(self.nonce_dir, f'nonce_{nonce}.lock')
        try:
            # os.unlink es atómico en POSIX y Windows moderno
            os.unlink(file_path)
            return True
        except OSError:
            # El archivo no existía (ya fue consumido o expiró)
            return False

    def clear_all_nonces(self) -> int:
        files = glob.glob(os.path.join(self.nonce_dir, 'nonce_*.lock'))
        count = 0
        for file_path in files:
            try:
                os.unlink(file_path)
                count += 1
            except OSError:
                pass
        return count

    def gc_nonces(self) -> None:
        files = glob.glob(os.path.join(self.nonce_dir, 'nonce_*.lock'))
        # Limpieza si hay muchos archivos o con probabilidad de 1%
        if len(files) > 50 or random.randint(1, 100) == 1:
            now = time.time()
            for file_path in files:
                try:
                    if os.path.isfile(file_path) and (now - os.path.getmtime(file_path) > 1200): # 20 min TTL
                        os.unlink(file_path)
                except OSError:
                    pass


# ==============================================================================
# CLIENTE PRINCIPAL
# ==============================================================================

class CrafyCAPTCHA:
    def __init__(self, public_key: str, secret_key: str, base_url: str = 'https://captcha.crafy.net/api'):
        self.public_key = public_key
        self.secret_key = secret_key
        self.base_url = base_url.rstrip('/')

        # Configuración del cliente HTTP
        self.timeout = 10
        self.max_retries = 3
        self.base_delay_ms = 500
        self.retry_status_codes = [429, 500, 502, 503, 504]

        # Estado interno
        self.access_token = None
        self.public_token = None
        self.last_flow_verify_error = None
        self._cryptor = _Cryptor(self.secret_key)

        # Almacenamiento por defecto: Archivos temporales del SO
        self.storage = FileStorage(tempfile.gettempdir())

    def set_storage(self, storage_adapter: StorageAdapter):
        """Inyecta un motor de almacenamiento personalizado."""
        self.storage = storage_adapter
        return self

    def set_temp_dir(self, path: str):
        """DEPRECADO: Utiliza set_storage(FileStorage(path))"""
        self.storage = FileStorage(path)
        return self

    def set_max_retries(self, retries: int):
        self.max_retries = max(0, retries)
        return self

    def set_base_delay_ms(self, milliseconds: int):
        self.base_delay_ms = max(0, milliseconds)
        return self

    def set_retry_status_codes(self, codes: list):
        self.retry_status_codes = codes
        return self

    def _get_cache_key(self) -> str:
        hash_str = hashlib.md5((self.public_key + self.secret_key).encode('utf-8')).hexdigest()
        return f'crafy_token_{hash_str}'

    def get_public_token(self) -> str:
        """Obtiene el Public Token dinámicamente."""
        self._ensure_auth()
        return self.public_token

    def create_flow(self, options: dict = None) -> str:
        """Crea un nuevo Flow seguro para el cliente."""
        if options is None:
            options = {}

        nonce = os.urandom(32).hex()
        expires_at = int(time.time()) + 1200 # TTL 20 mins

        # Almacenamos el nonce delegando al motor de Storage
        self.storage.store_nonce(nonce, expires_at)

        flow_data = options.copy()
        flow_data['nonce'] = nonce
        json_options = json.dumps(flow_data)

        return self._cryptor.encrypt(json_options)

    def verify_flow(self, base64_payload: str) -> bool:
        """Verifica un Flow completado sin llamar a la API externa."""
        self.last_flow_verify_error = None

        if not base64_payload:
            self.last_flow_verify_error = 'El token está vacío.'
            return False

        try:
            json_envelope = base64.b64decode(base64_payload).decode('utf-8')
            envelope = json.loads(json_envelope)
        except Exception:
            self.last_flow_verify_error = 'No se pudo decodificar el token.'
            return False

        payload_json = envelope.get('payload')
        signature = envelope.get('server_sign')

        if not payload_json or not signature:
            self.last_flow_verify_error = 'Token malformado.'
            return False

        # Validar Firma
        expected_signature = hmac.new(
            self.secret_key.encode('utf-8'),
            payload_json.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(expected_signature, signature):
            self.last_flow_verify_error = 'Firma de seguridad inválida.'
            return False

        try:
            data = json.loads(payload_json)
        except Exception:
            self.last_flow_verify_error = 'No se pudo decodificar el payload interno.'
            return False

        if data.get('status') != 'success':
            self.last_flow_verify_error = 'Estado de Flow inválido.'
            return False

        expires_at_str = data.get('expires_at')
        if not expires_at_str:
            self.last_flow_verify_error = 'Fecha de expiración no definida.'
            return False

        try:
            clean_date = expires_at_str.replace('Z', '+00:00')
            expires_at = datetime.fromisoformat(clean_date)
            
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
                
            now = datetime.now(timezone.utc)

            if now > expires_at:
                self.last_flow_verify_error = 'Token expirado.'
                return False
                
        except Exception as e:
            self.last_flow_verify_error = f'Fecha de expiración inválida. Detalles: {str(e)}'
            return False

        nonce_encrypted = data.get('nonce')
        if not nonce_encrypted:
            self.last_flow_verify_error = 'Nonce no encontrado.'
            return False

        decrypted_nonce = self._cryptor.decrypt(nonce_encrypted)

        if not decrypted_nonce:
            self.last_flow_verify_error = 'No se pudo decodificar el nonce.'
            return False

        clean_nonce = re.sub(r'[^a-f0-9]', '', decrypted_nonce)
        if clean_nonce != decrypted_nonce:
            self.last_flow_verify_error = 'Nonce inválido.'
            return False

        # Intento de consumo atómico delegando al motor de Storage
        if not self.storage.consume_nonce(clean_nonce):
            self.last_flow_verify_error = 'Nonce ya utilizado (Replay Attack).'
            return False

        # Garbage Collection delegada
        self.storage.gc_nonces()

        return True

    def get_last_flow_verify_error(self) -> str:
        return self.last_flow_verify_error

    def clear_all_nonces(self) -> int:
        return self.storage.clear_all_nonces()

    def call(self, action: str, data: dict = None) -> dict:
        if data is None:
            data = {}
            
        self._ensure_auth()

        try:
            return self._send_request(action, data, True)
        except Exception as e:
            if getattr(e, 'status_code', None) == 401 or '401' in str(e):
                self._clear_cache()
                self._ensure_auth(force_refresh=True)
                return self._send_request(action, data, True)
            raise e

    def _ensure_auth(self, force_refresh: bool = False):
        if not force_refresh and self.access_token and self.public_token:
            return

        if not force_refresh:
            raw_content = self.storage.get_cache(self._get_cache_key())
            if raw_content:
                decrypted = self._cryptor.decrypt(raw_content)
                if decrypted:
                    try:
                        cached = json.loads(decrypted)
                        if cached.get('token') and cached.get('public_token') and cached.get('expires_at'):
                            if time.time() < (cached['expires_at'] - 60):
                                self.access_token = cached['token']
                                self.public_token = cached['public_token']
                                return
                    except Exception:
                        pass 

        auth_payload = {'public_key': self.public_key, 'secret_key': self.secret_key}
        response = self._send_request('authenticate', auth_payload, False)

        if not response.get('token') or not response.get('public_token'):
            raise Exception("CrafyCAPTCHA SDK: Error en la respuesta de autenticación.")

        self.access_token = response['token']
        self.public_token = response['public_token']
        
        expires_in = int(response.get('expires_in', 86400))
        self._save_cache(self.access_token, self.public_token, int(time.time()) + expires_in)

    def _save_cache(self, token: str, public_token: str, expires_at: int):
        data_to_cache = json.dumps({
            'token': token, 
            'public_token': public_token,
            'expires_at': expires_at
        })
        
        encrypted_data = self._cryptor.encrypt(data_to_cache)
        self.storage.set_cache(self._get_cache_key(), encrypted_data, expires_at)

    def _clear_cache(self):
        self.access_token = None
        self.public_token = None
        self.storage.delete_cache(self._get_cache_key())

    def _send_request(self, action: str, data: dict, use_auth: bool) -> dict:
        url = f"{self.base_url}/?action={action}"
        
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': 'CrafyCAPTCHA-Python-SDK/2.2'
        }

        if use_auth and self.access_token:
            headers['Authorization'] = f"Bearer {self.access_token}"

        attempt = 0
        max_attempts = self.max_retries + 1

        while attempt < max_attempts:
            attempt += 1
            
            try:
                response = requests.post(url, json=data, headers=headers, timeout=self.timeout)
                http_code = response.status_code
                
                should_retry = http_code in self.retry_status_codes
                
                if should_retry and attempt < max_attempts:
                    delay_us = 0
                    retry_after = response.headers.get('Retry-After')
                    
                    if retry_after:
                        if retry_after.isdigit():
                            delay_us = int(retry_after) * 1000000
                        else:
                            try:
                                from email.utils import parsedate_to_datetime
                                dt = parsedate_to_datetime(retry_after)
                                delta = (dt - datetime.now(timezone.utc)).total_seconds()
                                if delta > 0:
                                    delay_us = int(delta * 1000000)
                            except Exception:
                                pass

                    if delay_us <= 0:
                        delay_us = int((self.base_delay_ms * 1000) * (2 ** (attempt - 1)))
                        
                    time.sleep(delay_us / 1000000.0)
                    continue

                if http_code == 401:
                    error = Exception("Unauthorized")
                    error.status_code = 401
                    raise error

                try:
                    json_resp = response.json()
                except ValueError:
                    if http_code >= 400:
                        error = Exception(f"CrafyCAPTCHA HTTP Error ({http_code})")
                        error.status_code = http_code
                        raise error
                    raise Exception(f"CrafyCAPTCHA API Error: Respuesta inválida. HTTP Code: {http_code}")

                if json_resp.get('status') == 'error':
                    msg = json_resp.get('message', 'Error desconocido')
                    error = Exception(msg)
                    error.status_code = http_code
                    raise error

                if http_code >= 400:
                    error = Exception(f"CrafyCAPTCHA HTTP Error ({http_code})")
                    error.status_code = http_code
                    raise error

                return json_resp.get('data', {})

            except requests.exceptions.RequestException as e:
                if attempt >= max_attempts:
                    raise Exception(f"CrafyCAPTCHA Network Error: {str(e)}")
                
                delay = (self.base_delay_ms / 1000.0) * (2 ** (attempt - 1))
                time.sleep(delay)

        raise Exception("CrafyCAPTCHA: Max retries exceeded.")