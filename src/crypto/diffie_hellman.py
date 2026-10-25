from .number_theory import modular_power
from .parameters import (
    Parameters,
    generate_private_key,
    validate_private_key,
    validate_public_key,
)


def generate_public_key(parameters: Parameters, private_key: int) -> int:
    validate_private_key(parameters, private_key)
    return modular_power(parameters.g, private_key, parameters.p)


def generate_key_pair(parameters: Parameters) -> tuple[int, int]:
    private_key = generate_private_key(parameters)
    public_key = generate_public_key(parameters, private_key)
    return private_key, public_key


def compute_shared_secret(
    parameters: Parameters, private_key: int, peer_public_key: int
) -> int:
    validate_private_key(parameters, private_key)
    validate_public_key(parameters, peer_public_key)
    return modular_power(peer_public_key, private_key, parameters.p)
