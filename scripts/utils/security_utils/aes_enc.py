import base64

from Cryptodome import Random
from Cryptodome.Cipher import AES


class AESCipher:
    """
    A classical AES Cipher. Can use any size of data and any size of password thanks to padding.
    Also ensure the coherence and the type of the data with a unicode to byte converter.
    """

    def __init__(self, key):
        self.bs = 16
        self.key = AESCipher.str_to_bytes(key)

    @staticmethod
    def str_to_bytes(data):
        u_type = type(b"".decode("utf8"))
        return data.encode("utf8") if isinstance(data, u_type) else data

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * AESCipher.str_to_bytes(chr(self.bs - len(s) % self.bs))

    @staticmethod
    def _unpad(s):
        return s[: -ord(s[-1:])]

    def encrypt(self, raw):
        raw = self._pad(AESCipher.str_to_bytes(raw))
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_GCM, iv)
        return base64.b64encode(iv + cipher.encrypt(raw)).decode("utf-8")

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[: AES.block_size]
        cipher = AES.new(self.key, AES.MODE_GCM, iv)
        data = self._unpad(cipher.decrypt(enc[AES.block_size :]))
        return data.decode("utf-8")
