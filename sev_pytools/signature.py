# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# Digital signature handling for AMD SEV-SNP attestation reports.

import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import utils

R_S_SIZE = 144  # 72 + 72


@dataclass
class Signature:
    """
    Signature
    Description: Represents a digital signature with 'r' and 's' components
    """

    r: bytes
    s: bytes
    _reserved: bytes

    def __init__(self, r: bytes, s: bytes):
        """
        __init__
        Description: Initialize a Signature object
        Inputs:
            r: bytes: The 'r' component of the signature (72 bytes)
            s: bytes: The 's' component of the signature (72 bytes)
        Output: None
        """
        if len(r) != 72 or len(s) != 72:
            raise ValueError("Both 'r' and 's' must be 72 bytes long")
        self.r = r
        self.s = s
        self._reserved = bytes(512 - R_S_SIZE)

    def get_r(self) -> bytes:
        """
        get_r
        Description: Get the 'r' component of the signature
        Input: None
        Output: bytes: The 'r' component
        """
        return self.r

    def get_s(self) -> bytes:
        """
        get_s
        Description: Get the 's' component of the signature
        Input: None
        Output: bytes: The 's' component
        """
        return self.s

    def get_trimmed_r(self) -> bytes:
        """
        get_trimmed_r
        Description: Get the 'r' component with trailing zeros removed
        Input: None
        Output: bytes: The trimmed 'r' component
        """
        return self.r.rstrip(b"\x00")

    def get_trimmed_s(self) -> bytes:
        """
        get_trimmed_s
        Description: Get the 's' component with trailing zeros removed
        Input: None
        Output: bytes: The trimmed 's' component
        """
        return self.s.rstrip(b"\x00")

    @classmethod
    def from_bytes(cls, data: bytes):
        """
        from_bytes
        Description: Create a Signature object from bytes
        Input: data: bytes: 512 bytes of signature data
        Output: Signature: A new Signature object
        """
        if len(data) != 512:
            raise ValueError("Input data must be 512 bytes long")
        return cls(r=data[:72], s=data[72:144])

    def to_bytes(self) -> bytes:
        """
        to_bytes
        Description: Convert the Signature object to its byte representation
        Input: None
        Output: bytes: 512-byte representation of the signature
        """
        return self.r + self.s + self._reserved

    def to_cryptography(self) -> bytes:
        """
        to_cryptography
        Description: Convert the Signature to a DER-encoded signature bytes object
        Input: None
        Output: bytes: DER-encoded signature
        """
        r_int = int.from_bytes(self.get_trimmed_r(), "big")
        s_int = int.from_bytes(self.get_trimmed_s(), "big")

        return utils.encode_dss_signature(r_int, s_int)

    def __repr__(self):
        """
        __repr__
        Description: Get a string representation of the Signature object
        Input: None
        Output: str: String representation of the Signature
        """
        return f"Signature(r={self.r.hex()}, s={self.s.hex()})"
