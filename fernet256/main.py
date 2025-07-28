# Libraries
import hmac
import time
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# Decryption Error
class DecryptionError(Exception):
    def __init__(self, *args):
        super().__init__(*args)

# Length Error
class LengthError(Exception):
    def __init__(self, *args):
        super().__init__(*args)

# Time Up
class TimeUpError(Exception):
    def __init__(self, *args):
        super().__init__(*args)


# AES-256
class AES256:

    # Initialization
    def __init__(self, key: bytes):

        # 88 Length Base64 Encoded Key | 64 raw bytes > 88 encoded base64
        self._key=key

        # Information(s)
        self._VER=0x100 # <-- 256 decimal

        # Byte Lengths
        self.__VERSION_LEN=2
        self.__TIMESTAMP_LEN=8
        self.__IV_LEN=AES.block_size
        self.__HMAC_LEN=32
        
        # Control Key
        try:
            self._key=base64.urlsafe_b64decode(self._key) # Try Decode Key
            if len(self._key)!=64:
                raise LengthError("Incompatible key length!") # Raise Length Error
        
        except Exception as error:
            raise DecryptionError(f"Incompatible base64 format! {error}") # Raise Decode Error

    
    # Encrypt
    def Encrypt(self, Plain_Text: bytes) -> bytes:
        # Create Variables
        timestamp=int(time.time())
        iv=get_random_bytes(AES.block_size)

        # Create AES Obj, Get Cipher Text
        AesObj=AES.new(self._key[:32], AES.MODE_CBC, iv)
        cipher_text=AesObj.encrypt(pad(Plain_Text, AES.block_size))

        # Concate data, Create Hmac_sig & Encode with BASE64
        concated_data=self._VER.to_bytes(2, "big")+timestamp.to_bytes(8, "big")+iv+cipher_text
        hmac_signature=hmac.new(self._key[32:], concated_data, hashlib.sha256).digest()
        output=base64.urlsafe_b64encode(concated_data+hmac_signature)

        # Return Output
        return output
    

    # Decrypt
    def Decrypt(self, Cipher_Text: bytes, Time_To_Live: int = None) -> bytes:
        # Decode BASE64 on Data
        cipher_text=base64.urlsafe_b64decode(Cipher_Text)

        # Hmac Control
        hmac_signature=cipher_text[-self.__HMAC_LEN:]
        cipher_text_hmac_signature=hmac.new(self._key[32:], cipher_text[:-32], hashlib.sha256).digest()
        if not hmac.compare_digest(hmac_signature, cipher_text_hmac_signature):
            raise DecryptionError("Signature does not match!")
        
        # Extract Values
        ver=cipher_text[
            0:self.__VERSION_LEN
            ]
        
        timestamp=cipher_text[
            self.__VERSION_LEN:self.__VERSION_LEN + self.__TIMESTAMP_LEN
            ]
        
        iv=cipher_text[
            self.__VERSION_LEN + self.__TIMESTAMP_LEN:self.__VERSION_LEN + self.__TIMESTAMP_LEN + self.__IV_LEN
            ]

        # Version Control
        if self._VER!=int.from_bytes(ver, "big"):
            print(self._VER, ver)
            raise DecryptionError("Incompatible version!")
        
        # Timestamp Control
        if Time_To_Live is not None:
            if int(time.time()) - int.from_bytes(timestamp) > Time_To_Live:
                raise TimeUpError("The cipher text is outdated!")

        # Create AES Obj, Get Plain Text
        AesObj=AES.new(self._key[:32], AES.MODE_CBC, iv)
        plain_text=unpad(AesObj.decrypt(cipher_text[self.__VERSION_LEN+self.__TIMESTAMP_LEN+self.__IV_LEN:-self.__HMAC_LEN]), AES.block_size)

        # Return Output
        return plain_text


    # Generate Key
    @staticmethod
    def generate_key() -> bytes:
        return base64.urlsafe_b64encode(get_random_bytes(64))
