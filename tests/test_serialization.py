import unittest

from src.crypto import Parameters, elgamal
from src.crypto.serialization import ciphertext_from_hex, ciphertext_to_hex


class SerializationTests(unittest.TestCase):
    def test_known_format_preserves_leading_zeros_and_pair_order(self):
        parameters = Parameters(467, 2)
        pairs = [(10, 14), (466, 0)]
        self.assertEqual(ciphertext_to_hex(parameters, pairs), "000a000e01d20000")
        self.assertEqual(ciphertext_from_hex(parameters, "000A000E01D20000"), pairs)

    def test_text_round_trip_across_integer_widths(self):
        for parameters in [Parameters(257, 3), Parameters(467, 2), Parameters(65537, 3)]:
            public = elgamal.generate_public_key(parameters, 6)
            for message in ["", "hello", "  café 🌏  ", "\x00"]:
                ciphertext = elgamal.encrypt_text(parameters, public, message)
                encoded = ciphertext_to_hex(parameters, ciphertext)
                decoded = ciphertext_from_hex(parameters, encoded)
                self.assertEqual(decoded, ciphertext)
                self.assertEqual(elgamal.decrypt_text(parameters, 6, decoded), message)

    def test_invalid_hex_lengths_and_residues(self):
        parameters = Parameters(467, 2)
        for text in ["xyz", "0", "00", "000a00", "00010002", "000201d3"]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                ciphertext_from_hex(parameters, text)
        for pair in [(1, 14), (10, -1), (10, 467)]:
            with self.subTest(pair=pair), self.assertRaises(ValueError):
                ciphertext_to_hex(parameters, [pair])


if __name__ == "__main__":
    unittest.main()
