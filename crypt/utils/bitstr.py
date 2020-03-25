from itertools import chain


def unpack(bits, base, chunk):
    res = []
    buffer = []

    for i in chain.from_iterable(bits):
        buffer.append(i)

        if len(buffer) >= chunk:
            buffer_iter = (str(i) for i in buffer)

            value = "".join(buffer_iter)
            value = int(value, base=base)

            char = chr(value)
            res.append(char)

            buffer.clear()

    return "".join(res)


def bits_to_str(seq, chunk=16):
    return unpack(seq, 2, chunk)


def str_to_bits(s, chunk=16):
    format_expr = "0={0}b".format(chunk)
    bits_iter = (format(ord(i), format_expr) for i in s)

    return ''.join(bits_iter)


def positive_align_str(s, chunk, fill_char="0"):
    str_length = len(s)
    excess = str_length % chunk

    if excess > 0:
        full_len = str_length + (chunk - excess)

        return s.ljust(full_len, fill_char)

    return s


def iterable_to_str(seq):
    iterator = (str(i) for i in chain.from_iterable(seq))
    return "".join(iterator)
