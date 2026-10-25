from .crypto import Parameters, diffie_hellman, elgamal, generate_parameters
from .crypto.parameters import generate_private_key
from .crypto.serialization import ciphertext_from_hex, ciphertext_to_hex


def read_integer(
    prompt: str,
    minimum: int,
    maximum: int,
    default: int | None = None,
) -> int:
    while True:
        text = input(prompt).strip()
        if not text and default is not None:
            return default
        try:
            value = int(text)
        except ValueError:
            print("Please enter a whole number.")
            continue
        if minimum <= value <= maximum:
            return value
        print(f"Please enter a number from {minimum} to {maximum}.")


def read_private_key(parameters: Parameters, name: str) -> int:
    text = input(f"{name} private key (1..{parameters.p - 2}, Enter = random): ").strip()
    while text:
        try:
            value = int(text)
            if 1 <= value <= parameters.p - 2:
                return value
        except ValueError:
            pass
        print(f"Please enter a whole number from 1 to {parameters.p - 2}.")
        text = input(f"{name} private key (Enter = random): ").strip()
    return generate_private_key(parameters)


def choose_parameters(current: Parameters) -> Parameters:
    print("\n1. Use example parameters (p=23, g=5)")
    print("2. Generate parameters")
    print("3. Enter parameters manually")
    print("0. Back")
    choice = read_integer("Choose: ", 0, 3)
    if choice == 0:
        return current
    if choice == 1:
        return Parameters(p=23, g=5)
    if choice == 2:
        bits = read_integer("Prime size in bits (3..24, Enter = 16): ", 3, 24, 16)
        return generate_parameters(bits)
    while True:
        prime = read_integer("Prime p (5..16777215): ", 5, 16777215)
        generator = read_integer(f"Generator g (2..{prime - 1}): ", 2, prime - 1)
        try:
            return Parameters(p=prime, g=generator)
        except ValueError as error:
            print(f"Invalid parameters: {error}. Please try again.")


def run_diffie_hellman(parameters: Parameters) -> None:
    alice = read_private_key(parameters, "Alice")
    bob = read_private_key(parameters, "Bob")
    alice_public = diffie_hellman.generate_public_key(parameters, alice)
    bob_public = diffie_hellman.generate_public_key(parameters, bob)
    alice_secret = diffie_hellman.compute_shared_secret(parameters, alice, bob_public)
    bob_secret = diffie_hellman.compute_shared_secret(parameters, bob, alice_public)

    print(f"\nAlice private key a = {alice}")
    print(f"Alice public key A = {parameters.g}^{alice} mod {parameters.p} = {alice_public}")
    print(f"Bob private key b = {bob}")
    print(f"Bob public key B = {parameters.g}^{bob} mod {parameters.p} = {bob_public}")
    print(f"Alice shared secret = {bob_public}^{alice} mod {parameters.p} = {alice_secret}")
    print(f"Bob shared secret = {alice_public}^{bob} mod {parameters.p} = {bob_secret}")
    print(f"Shared secrets match: {alice_secret == bob_secret}")


def create_elgamal_keys(parameters: Parameters) -> tuple[int, int]:
    private = read_private_key(parameters, "Recipient")
    public = elgamal.generate_public_key(parameters, private)
    print(f"\nRecipient private key x = {private}")
    print(f"Recipient public key y = {parameters.g}^{private} mod {parameters.p} = {public}")
    return private, public


def encrypt_message(
    parameters: Parameters, keys: tuple[int, int] | None
) -> tuple[int, int]:
    default = keys[1] if keys is not None else None
    hint = f", Enter = {default}" if default is not None else ""
    public = read_integer(
        f"Recipient public key (2..{parameters.p - 1}{hint}): ",
        2, parameters.p - 1, default,
    )
    message = read_integer(f"Integer message (0..{parameters.p - 1}): ", 0, parameters.p - 1)
    ciphertext = elgamal.encrypt(parameters, public, message)
    print(f"\nCiphertext (c1, c2) = {ciphertext}")
    print("A fresh random exponent was used for this encryption.")
    return ciphertext


def decrypt_message(
    parameters: Parameters,
    keys: tuple[int, int] | None,
    ciphertext: tuple[int, int] | None,
) -> None:
    default = keys[0] if keys is not None else None
    hint = f", Enter = {default}" if default is not None else ""
    private = read_integer(
        f"Recipient private key (1..{parameters.p - 2}{hint}): ",
        1, parameters.p - 2, default,
    )
    first = ciphertext[0] if ciphertext is not None else None
    second = ciphertext[1] if ciphertext is not None else None
    first_hint = f", Enter = {first}" if first is not None else ""
    second_hint = f", Enter = {second}" if second is not None else ""
    c1 = read_integer(f"c1 (2..{parameters.p - 1}{first_hint}): ", 2, parameters.p - 1, first)
    c2 = read_integer(f"c2 (0..{parameters.p - 1}{second_hint}): ", 0, parameters.p - 1, second)
    message = elgamal.decrypt(parameters, private, (c1, c2))
    print(f"\nRecovered message = {message}")


def encrypt_text_message(
    parameters: Parameters, keys: tuple[int, int] | None
) -> list[tuple[int, int]]:
    default = keys[1] if keys is not None else None
    hint = f", Enter = {default}" if default is not None else ""
    public = read_integer(
        f"Recipient public key (2..{parameters.p - 1}{hint}): ",
        2, parameters.p - 1, default,
    )
    message = input("Text message: ")
    ciphertext = elgamal.encrypt_text(parameters, public, message)
    print(f"\nText ciphertext (hex) = {ciphertext_to_hex(parameters, ciphertext)}")
    return ciphertext


def decrypt_text_message(
    parameters: Parameters,
    keys: tuple[int, int] | None,
    ciphertext: list[tuple[int, int]] | None,
) -> None:
    default = keys[0] if keys is not None else None
    hint = f", Enter = {default}" if default is not None else ""
    private = read_integer(
        f"Recipient private key (1..{parameters.p - 2}{hint}): ",
        1, parameters.p - 2, default,
    )
    hint = " (Enter = stored ciphertext)" if ciphertext is not None else ""
    while True:
        text = input(f"Text ciphertext as hex{hint}: ").strip()
        try:
            if not text and ciphertext is not None:
                pairs = ciphertext
            else:
                pairs = ciphertext_from_hex(parameters, text)
            message = elgamal.decrypt_text(parameters, private, pairs)
        except (ValueError, TypeError) as error:
            print(f"Cannot decrypt text: {error}")
            print("Try another ciphertext, or press Ctrl+C to exit and check your key.")
            continue
        print(f"\nRecovered text = {message}")
        return


def main() -> None:
    parameters = Parameters(p=467, g=2)
    keys = None
    ciphertext = None
    text_ciphertext = None
    print("Diffie-Hellman and ElGamal interactive CLI")
    print("Classroom mode: private keys are displayed to explain the calculations.")
    try:
        while True:
            print(f"\nPublic parameters: p={parameters.p}, g={parameters.g}")
            print("1. Configure public parameters")
            print("2. Diffie-Hellman key exchange")
            print("3. Create ElGamal keys")
            print("4. ElGamal encrypt")
            print("5. ElGamal decrypt")
            print("6. ElGamal encrypt text")
            print("7. ElGamal decrypt text")
            print("0. Exit")
            choice = read_integer("Choose: ", 0, 7)
            if choice == 0:
                break
            if choice == 1:
                new_parameters = choose_parameters(parameters)
                if new_parameters != parameters:
                    parameters = new_parameters
                    keys = None
                    ciphertext = None
                    text_ciphertext = None
                    print("Parameters updated. Stored keys and ciphertext cleared.")
            elif choice == 2:
                run_diffie_hellman(parameters)
            elif choice == 3:
                keys = create_elgamal_keys(parameters)
                ciphertext = None
                text_ciphertext = None
            elif choice == 4:
                ciphertext = encrypt_message(parameters, keys)
            elif choice == 5:
                decrypt_message(parameters, keys, ciphertext)
            elif choice in (6, 7):
                if parameters.p <= 256:
                    print("Text requires p greater than 256. Configure a larger prime with option 1.")
                    continue
                if choice == 6:
                    text_ciphertext = encrypt_text_message(parameters, keys)
                else:
                    decrypt_text_message(parameters, keys, text_ciphertext)
    except (EOFError, KeyboardInterrupt):
        print()
    print("Goodbye!")
