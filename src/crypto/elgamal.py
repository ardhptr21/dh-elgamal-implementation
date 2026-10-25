from .diffie_hellman import generate_key_pair, generate_public_key
from .number_theory import modular_inverse, modular_power, require_integer
from .parameters import (
    Parameters,
    generate_private_key,
    validate_private_key,
    validate_public_key,
)


def encrypt(
    parameters: Parameters, public_key: int, message: int
) -> tuple[int, int]:
    validate_public_key(parameters, public_key)
    require_integer(message, "message")
    if not 0 <= message < parameters.p:
        raise ValueError("message must be between 0 and p - 1")

    ephemeral_key = generate_private_key(parameters)
    c1 = generate_public_key(parameters, ephemeral_key)
    shared_secret = modular_power(public_key, ephemeral_key, parameters.p)
    c2 = (message * shared_secret) % parameters.p
    return c1, c2


def decrypt(
    parameters: Parameters, private_key: int, ciphertext: tuple[int, int]
) -> int:
    validate_private_key(parameters, private_key)
    if not isinstance(ciphertext, tuple) or len(ciphertext) != 2:
        raise ValueError("ciphertext must be a tuple containing (c1, c2)")
    c1, c2 = ciphertext
    validate_public_key(parameters, c1)
    require_integer(c2, "c2")
    if not 0 <= c2 < parameters.p:
        raise ValueError("c2 must be between 0 and p - 1")

    shared_secret = modular_power(c1, private_key, parameters.p)
    inverse_secret = modular_inverse(shared_secret, parameters.p)
    return (c2 * inverse_secret) % parameters.p


def encrypt_text(
    parameters: Parameters, public_key: int, message: str
) -> list[tuple[int, int]]:
    if parameters.p <= 256:
        raise ValueError("text encryption requires p greater than 256")
    validate_public_key(parameters, public_key)
    if not isinstance(message, str):
        raise TypeError("message must be a string")
    return [encrypt(parameters, public_key, byte + 1) for byte in message.encode("utf-8")]


def decrypt_text(
    parameters: Parameters, private_key: int, ciphertext: list[tuple[int, int]]
) -> str:
    if parameters.p <= 256:
        raise ValueError("text decryption requires p greater than 256")
    validate_private_key(parameters, private_key)
    if not isinstance(ciphertext, list):
        raise ValueError("text ciphertext must be a list of pairs")
    recovered_bytes = []
    for pair in ciphertext:
        value = decrypt(parameters, private_key, pair)
        if not 1 <= value <= 256:
            raise ValueError("decrypted value is outside the encoded byte range")
        recovered_bytes.append(value - 1)
    try:
        return bytes(recovered_bytes).decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("decrypted bytes are not valid UTF-8; check the key and ciphertext") from error
