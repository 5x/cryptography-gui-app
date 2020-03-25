from itertools import product


class DecryptIter(object):
    def __init__(self, cipher, message, chars, key_range_limit):
        self.cipher = cipher
        self.message = message
        self.chars = chars
        self.range = key_range_limit

    def __iter__(self):
        for key_length in range(*self.range):
            key_iter = product(self.chars, repeat=key_length)

            for key_tuple in key_iter:
                try:
                    self.cipher.key = ''.join(key_tuple)
                except ValueError:
                    pass
                else:
                    pain_text = self.cipher.decrypt(self.message)
                    yield (self.cipher.key, pain_text)
