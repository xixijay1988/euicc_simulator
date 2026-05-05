"""
SCP03t (Secure Channel Protocol 03 - transport) implementation.

Used for BoundProfilePackage (BPP) decryption per SGP.22 §5.7.
Also known as BSP (BPP Security Protocol) in some GSMA docs.

SCP03t uses:
- AES-CBC for encryption (with zero IV for each command)
- AES-CMAC for integrity (MAC)
- Session keys derived via ECDH (see ecdsa_engine.SessionKeys)
"""

import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives import padding as sym_padding

from .ecdsa_engine import SessionKeys


class Scp03tProcessor:
    """
    Processes SCP03t-secured command/response APDUs.

    In the profile download flow:
    1. SM-DP+ encrypts profile elements with S-ENC
    2. SM-DP+ MACs each segment with S-MAC
    3. eUICC verifies MAC, then decrypts
    """

    def __init__(self, session_keys: SessionKeys):
        self.session_keys = session_keys
        self._mac_chaining_value = b"\x00" * 16  # AES block size
        self._encryption_counter = 0

    def verify_and_decrypt(self, secured_data: bytes) -> bytes | None:
        """
        Verify MAC and decrypt an SCP03t-secured data block.

        Format per GP Amendment F:
        - Data = encrypted_data || mac (last 8 bytes)
        - MAC is computed over encrypted_data using chained AES-CMAC

        Returns decrypted data or None if MAC verification fails.
        """
        if len(secured_data) < 8:
            return None

        encrypted_data = secured_data[:-8]
        received_mac = secured_data[-8:]

        # Verify MAC (AES-CMAC with S-MAC key, truncated to 8 bytes)
        computed_mac = self._compute_mac(encrypted_data)
        if computed_mac[:8] != received_mac:
            return None

        # Decrypt (AES-CBC with S-ENC key)
        decrypted = self._decrypt(encrypted_data)
        return decrypted

    def decrypt_profile_element(self, encrypted_element: bytes) -> bytes:
        """
        Decrypt a single profile element from the BPP.

        Each profile element in sequenceOf87 is individually encrypted.
        Uses AES-CBC with a counter-derived IV.
        """
        iv = self._generate_encryption_iv()
        self._encryption_counter += 1

        cipher = Cipher(
            algorithms.AES128(self.session_keys.s_enc),
            modes.CBC(iv),
        )
        decryptor = cipher.decryptor()
        padded = decryptor.update(encrypted_element) + decryptor.finalize()

        # Remove ISO/IEC 9797-1 padding (method 2): 80 00 00 ...
        return self._remove_padding(padded)

    def compute_response_mac(self, response_data: bytes) -> bytes:
        """Compute response MAC using S-RMAC key."""
        c = CMAC(algorithms.AES128(self.session_keys.s_rmac))
        c.update(self._mac_chaining_value + response_data)
        mac = c.finalize()
        return mac[:8]

    def _compute_mac(self, data: bytes) -> bytes:
        """
        Compute AES-CMAC with MAC chaining.

        MAC input = previous_mac_chaining_value || data
        New chaining value = full MAC output
        """
        c = CMAC(algorithms.AES128(self.session_keys.s_mac))
        c.update(self._mac_chaining_value + data)
        mac = c.finalize()

        # Update chaining value for next MAC computation
        self._mac_chaining_value = mac
        return mac

    def _decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypt using AES-CBC with counter-derived IV."""
        iv = self._generate_encryption_iv()
        self._encryption_counter += 1

        cipher = Cipher(
            algorithms.AES128(self.session_keys.s_enc),
            modes.CBC(iv),
        )
        decryptor = cipher.decryptor()
        padded = decryptor.update(encrypted_data) + decryptor.finalize()
        return self._remove_padding(padded)

    def _generate_encryption_iv(self) -> bytes:
        """
        Generate IV for AES-CBC encryption/decryption.

        Per SCP03: IV = AES-ECB(S-ENC, counter_block)
        counter_block = 00...00 || counter (16 bytes total)
        """
        counter_block = self._encryption_counter.to_bytes(16, byteorder="big")
        cipher = Cipher(
            algorithms.AES128(self.session_keys.s_enc),
            modes.ECB(),
        )
        encryptor = cipher.encryptor()
        iv = encryptor.update(counter_block) + encryptor.finalize()
        return iv

    @staticmethod
    def _remove_padding(data: bytes) -> bytes:
        """
        Remove ISO/IEC 9797-1 Method 2 padding.

        Padding: data || 0x80 || 0x00 ... 0x00
        Find the last 0x80 byte and strip it and trailing zeros.
        """
        # Search backwards for the 0x80 padding byte
        idx = len(data) - 1
        while idx >= 0 and data[idx] == 0x00:
            idx -= 1
        if idx >= 0 and data[idx] == 0x80:
            return data[:idx]
        # No padding found, return as-is
        return data
