from random import Random

from crypt.trithemius_cipher import TrithemiusCipher, TrithemiusHandleABC
from crypt.cipher_abc import CipherABC


class SimplePRNG(TrithemiusHandleABC):
    SHIFT_C1 = 53

    def __init__(self, symbols_collection, key, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._symbols_len = len(symbols_collection)
        self._random_inst = Random(x=key)

    def __iter__(self):
        while True:
            rand_int = self._random_inst.randint(0, self._symbols_len)
            next_val = (rand_int + SimplePRNG.SHIFT_C1) % self._symbols_len

            yield next_val

    def get_code(self, index):
        return next(self.__iter__())


class GammaCipher(TrithemiusCipher):
    def __init__(self, key, alphabet='EN'):
        super().__init__(key, SimplePRNG, alphabet)

    @CipherABC.key.setter
    def key(self, value):
        self._key = int(value)


if __name__ == "__main__":
    cipher = GammaCipher("54")
    crt_text = cipher.encrypt("the quick brown fox jumps over the lazy dog.")
    plain_text = cipher.decrypt(crt_text)

    print(crt_text)
    print(plain_text)
