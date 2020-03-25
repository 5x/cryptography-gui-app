from crypt.alphabet import get_alphabet
from crypt.cipher_abc import CipherABC


class CaesarCipher(CipherABC):
    def __init__(self, key, alphabet='EN'):
        super().__init__(key)
        self.symbols_collection = get_alphabet(alphabet)

    @CipherABC.key.setter
    def key(self, value):
        self._key = int(value)

    def encrypt(self, plain_text):
        return self._shift_msg(self._key, plain_text)

    def decrypt(self, cipher_text):
        return self._shift_msg(-self._key, cipher_text)

    def _shift_msg(self, key, message):
        shift_map = self._shift_map(key)
        shifted_msg = (shift_map.get(char, char) for char in message)

        return "".join(shifted_msg)

    def _shift_map(self, shift):
        assoc_map = {}

        for symbols in self.symbols_collection:
            symbols_len = len(symbols)

            if symbols_len == 0:
                continue

            for j in range(symbols_len):
                in_char = symbols[j]
                shifted = (j + shift) % symbols_len
                assoc_map[in_char] = symbols[shifted]

        return assoc_map


if __name__ == "__main__":
    cipher = CaesarCipher("4")
    crt_text = cipher.encrypt("the quick brown fox jumps over the lazy dog.")
    plain_text = cipher.decrypt(crt_text)

    print(crt_text)
    print(plain_text)
