from .en import translation


class TranslationType(type):
    def __getattr__(cls, key):
        return translation.get(key, 'i10n error. Key not defined!')


class i10n(metaclass=TranslationType):
    pass
