import secrets
from dataclasses import dataclass

from .number_theory import (
    find_primitive_root,
    generate_prime,
    is_primitive_root,
    require_integer,
)


@dataclass(frozen=True)
class Parameters:

    p: int
    g: int

    def __post_init__(self) -> None:
        require_integer(self.p, "p")
        require_integer(self.g, "g")
        if self.p < 5:
            raise ValueError("p must be a prime of at least 5")
        if not is_primitive_root(self.g, self.p):
            raise ValueError("g must be a primitive root modulo p")


def generate_parameters(bits: int = 16) -> Parameters:
    require_integer(bits, "bits")
    if bits < 3:
        raise ValueError("bits must be at least 3")
    prime = generate_prime(bits)
    return Parameters(p=prime, g=find_primitive_root(prime))


def validate_private_key(parameters: Parameters, private_key: int) -> None:
    require_integer(private_key, "private_key")
    if not 1 <= private_key <= parameters.p - 2:
        raise ValueError("private_key must be between 1 and p - 2")


def validate_public_key(parameters: Parameters, public_key: int) -> None:
    require_integer(public_key, "public_key")
    if not 2 <= public_key < parameters.p:
        raise ValueError("public_key must be between 2 and p - 1")


def generate_private_key(parameters: Parameters) -> int:
    return secrets.randbelow(parameters.p - 2) + 1
