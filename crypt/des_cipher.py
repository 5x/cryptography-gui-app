import hashlib
from base64 import b64encode, b64decode

from Crypto import Random
from Crypto.Cipher import DES

from crypt.cipher_abc import CipherABC
from crypt.utils.bitstr import str_to_bits, positive_align_str, bits_to_str


class DESCipher(CipherABC):
    def __init__(self, key):
        super().__init__(key)

    @CipherABC.key.setter
    def key(self, value):
        string_utf = value.encode()
        hash_value = hashlib.md5(string_utf)
        value = hash_value.hexdigest()
        value = value[:8].encode()

        self._key = value

    def encrypt(self, plain_text):
        text = str_to_bits(plain_text)
        text = positive_align_str(text, 16, "\0")
        data = text.encode()

        iv = Random.new().read(DES.block_size)
        cipher = DES.new(self.key, DES.MODE_CFB, iv)

        data = iv + cipher.encrypt(data)
        cipher_text = b64encode(data).decode()

        return cipher_text

    def decrypt(self, cipher_text):
        enc = b64decode(cipher_text.encode())
        iv = enc[:DES.block_size]
        cipher = DES.new(self.key, DES.MODE_CFB, iv)

        enc_data = enc[DES.block_size:]

        plain_bytes = cipher.decrypt(enc_data)
        plain_decoded_bytes = plain_bytes.decode()
        plain_text = bits_to_str(plain_decoded_bytes)
        plain_text.rstrip("\0")

        return plain_text


if __name__ == "__main__":
    c = DESCipher("f1")
    f = c.encrypt("""
The quick brown fox jumps over the lazy dog.
The five boxing wizards jump quickly.
В Бахчисараї фельд'єґер зумів одягнути ящірці жовтий капюшон!
Жебракують філософи при ґанку церкви в Гадячі, ще й шатро їхнє п'яне знаємо
В чащах юга жил бы цитрус? Да, но фальшивый экземпляр!
Съешь [же] ещё этих мягких французских булок да выпей чаю.
Экс-граф? Плюш изъят. Бьём чуждый цен хвощ!""")
    t = c.decrypt(f)
    print(f)
    print(t)
