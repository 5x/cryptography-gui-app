from crypt.utils.number_theory_algs import extended_gcd
from crypt.utils.bitstr import str_to_bits, bits_to_str, positive_align_str
from crypt.utils.knapsack import knapsack


class AsymmetricCipher(object):
    def encrypt(self, plain_text, public_seq):
        block_size = len(public_seq)
        text = str_to_bits(plain_text)
        text = positive_align_str(text, block_size)

        blocks = tuple(zip(*[iter(text)] * block_size))

        crt_values = []
        for index, block in enumerate(blocks):
            total_weight = self._block_total_weight(block, public_seq)
            crt_values.append(total_weight)

        return crt_values

    def decrypt(self, cipher_text, private_seq, m, t):
        _, _, neg_t = extended_gcd(m, t)

        plain_bits = []
        for num in cipher_text:
            value = (neg_t * num) % m
            bits_block = knapsack(private_seq, value)
            plain_bits.append(bits_block)

        plain_text = bits_to_str(plain_bits)

        return plain_text

    @staticmethod
    def gen_public_key(secret_sec, t, m):
        return [(t * i) % m for i in secret_sec]

    def _block_total_weight(self, bits, weight_values):
        return sum(w for w, bit in zip(weight_values, bits) if bit == "1")


if __name__ == "__main__":
    test_data = """The quick brown fox jumps over the lazy dog."""
    secret_key = [1, 3, 5, 11, 21, 44, 87, 175, 349, 701]
    s = 1590
    m = 43

    cipher = AsymmetricCipher()

    # eq [43, 129, 215, 473, 903, 302, 561, 1165, 697, 1523]
    public_key = AsymmetricCipher.gen_public_key(secret_key, m, s)
    crt_text = cipher.encrypt(test_data, public_key)
    plain_text = cipher.decrypt(crt_text, secret_key, s, m)

    print(public_key)
    print(crt_text)
    print(plain_text)
