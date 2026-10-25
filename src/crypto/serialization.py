from .number_theory import require_integer
from .parameters import Parameters, validate_public_key


def ciphertext_to_hex(parameters: Parameters, ciphertext: list[tuple[int, int]]) -> str:
    width = (parameters.p.bit_length() + 7) // 8
    encoded = bytearray()
    for c1, c2 in ciphertext:
        validate_public_key(parameters, c1)
        require_integer(c2, "c2")
        if not 0 <= c2 < parameters.p:
            raise ValueError("c2 must be between 0 and p - 1")
        encoded.extend(c1.to_bytes(width, "big"))
        encoded.extend(c2.to_bytes(width, "big"))
    return encoded.hex()


def ciphertext_from_hex(parameters: Parameters, text: str) -> list[tuple[int, int]]:
    width = (parameters.p.bit_length() + 7) // 8
    data = bytes.fromhex(text)
    if len(data) % (2 * width) != 0:
        raise ValueError("hex ciphertext contains an incomplete pair")
    ciphertext = []
    for offset in range(0, len(data), 2 * width):
        c1 = int.from_bytes(data[offset:offset + width], "big")
        c2 = int.from_bytes(data[offset + width:offset + 2 * width], "big")
        validate_public_key(parameters, c1)
        if not 0 <= c2 < parameters.p:
            raise ValueError("c2 must be between 0 and p - 1")
        ciphertext.append((c1, c2))
    return ciphertext
