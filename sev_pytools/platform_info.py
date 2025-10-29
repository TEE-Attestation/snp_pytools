# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# Platform information parsing and management for AMD SEV-SNP attestation.

from typing import Dict, List


class PlatformInfo:
    """
    PlatformInfo - Represents platform information with various configurable options

    This class handles the platform information flags found in AMD SEV-SNP attestation reports.
    Each bit in the platform information field represents a different platform feature or capability.

    Supported flags:
    - Bit 0: SMT (Simultaneous Multi-Threading) enabled
    - Bit 1: TSME (Transparent Secure Memory Encryption) enabled
    - Bit 2: ECC (Error-Correcting Code) memory enabled
    - Bit 3: RAPL (Running Average Power Limit) disabled
    - Bit 4: Ciphertext hiding enabled
    - Bit 5: ALIAS_CHECK_COMPLETE - Alias check completed successfully
    - Bit 7: TIO_EN (Trusted I/O) enabled
    """

    def __init__(self, value: int = 0) -> None:
        """
        Initialize a PlatformInfo object.

        Args:
            value: The initial value of the platform info (default: 0)
        """
        self._value = value

    @property
    def value(self) -> int:
        """Get the raw platform information value."""
        return self._value

    @value.setter
    def value(self, val: int) -> None:
        """Set the raw platform information value."""
        self._value = val

    def _get_bit(self, position: int) -> bool:
        """
        Get the value of a specific bit in the platform info.

        Args:
            position: The bit position to check

        Returns:
            The value of the specified bit
        """
        return bool(self._value & (1 << position))

    def _set_bit(self, position: int, value: bool) -> None:
        """
        Set the value of a specific bit in the platform info.

        Args:
            position: The bit position to set
            value: The value to set (True for 1, False for 0)
        """
        if value:
            self._value |= 1 << position
        else:
            self._value &= ~(1 << position)

    @property
    def smt_enabled(self) -> bool:
        """
        Check if Simultaneous Multi-Threading (SMT) is enabled.

        SMT allows multiple threads to execute simultaneously on a single CPU core,
        potentially improving performance but may introduce side-channel vulnerabilities.

        Returns:
            True if SMT is enabled, False otherwise
        """
        return self._get_bit(0)

    @smt_enabled.setter
    def smt_enabled(self, value: bool) -> None:
        """Set whether Simultaneous Multi-Threading (SMT) is enabled."""
        self._set_bit(0, value)

    @property
    def tsme_enabled(self) -> bool:
        """
        Check if Transparent Secure Memory Encryption (TSME) is enabled.

        TSME encrypts all system memory transparently without requiring
        software modifications, providing protection against physical attacks.

        Returns:
            True if TSME is enabled, False otherwise
        """
        return self._get_bit(1)

    @tsme_enabled.setter
    def tsme_enabled(self, value: bool) -> None:
        """Set whether Transparent Secure Memory Encryption (TSME) is enabled."""
        self._set_bit(1, value)

    @property
    def ecc_enabled(self) -> bool:
        """
        Check if Error-Correcting Code (ECC) memory is enabled.

        ECC memory can detect and correct single-bit memory errors,
        improving system reliability and data integrity.

        Returns:
            True if ECC is enabled, False otherwise
        """
        return self._get_bit(2)

    @ecc_enabled.setter
    def ecc_enabled(self, value: bool) -> None:
        """Set whether Error-Correcting Code (ECC) memory is enabled."""
        self._set_bit(2, value)

    @property
    def rapl_disabled(self) -> bool:
        """
        Check if Running Average Power Limit (RAPL) is disabled.

        RAPL provides interfaces for monitoring and controlling CPU power consumption.
        Disabling RAPL prevents potential side-channel attacks based on power analysis.

        Returns:
            True if RAPL is disabled, False otherwise
        """
        return self._get_bit(3)

    @rapl_disabled.setter
    def rapl_disabled(self, value: bool) -> None:
        """Set whether Running Average Power Limit (RAPL) is disabled."""
        self._set_bit(3, value)

    @property
    def ciphertext_hiding_enabled(self) -> bool:
        """
        Check if ciphertext hiding is enabled.

        Ciphertext hiding obfuscates encrypted memory contents to prevent
        side-channel attacks that could infer information from memory access patterns.

        Returns:
            True if ciphertext hiding is enabled, False otherwise
        """
        return self._get_bit(4)

    @ciphertext_hiding_enabled.setter
    def ciphertext_hiding_enabled(self, value: bool) -> None:
        """Set whether ciphertext hiding is enabled."""
        self._set_bit(4, value)

    @property
    def alias_check_complete(self) -> bool:
        """
        Check if alias check completed successfully.

        Indicates that alias detection has completed since the
        last system reset and there are no aliasing addresses.
        Resets to 0.
        Contains mitigation for CVE-2024-21944.

        Returns:
            True if alias check completed successfully, False otherwise
        """
        return self._get_bit(5)

    @alias_check_complete.setter
    def alias_check_complete(self, value: bool) -> None:
        """Set whether alias check completed successfully."""
        self._set_bit(5, value)

    @property
    def tio_enabled(self) -> bool:
        """
        Check if Trusted I/O (TIO) is enabled.

        TIO provides a mechanism for guests to bind to and use trusted devices
        within their guest private address space, enhancing I/O security.

        Returns:
            True if TIO is enabled, False otherwise
        """
        return self._get_bit(7)

    @tio_enabled.setter
    def tio_enabled(self, value: bool) -> None:
        """Set whether Trusted I/O (TIO) is enabled."""
        self._set_bit(7, value)

    def get_enabled_features(self) -> List[str]:
        """
        Get a list of enabled platform features.

        Returns:
            List of feature names that are currently enabled
        """
        features = []
        if self.smt_enabled:
            features.append("SMT")
        if self.tsme_enabled:
            features.append("TSME")
        if self.ecc_enabled:
            features.append("ECC")
        if self.rapl_disabled:
            features.append("RAPL_DISABLED")
        if self.ciphertext_hiding_enabled:
            features.append("CIPHERTEXT_HIDING")
        if self.alias_check_complete:
            features.append("ALIAS_CHECK_COMPLETE")
        if self.tio_enabled:
            features.append("TIO_ENABLED")
        return features

    def to_dict(self) -> Dict[str, bool]:
        """
        Convert platform information to a dictionary.

        Returns:
            Dictionary mapping feature names to their enabled status
        """
        return {
            "smt_enabled": self.smt_enabled,
            "tsme_enabled": self.tsme_enabled,
            "ecc_enabled": self.ecc_enabled,
            "rapl_disabled": self.rapl_disabled,
            "ciphertext_hiding_enabled": self.ciphertext_hiding_enabled,
            "alias_check_complete": self.alias_check_complete,
            "tio_enabled": self.tio_enabled,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, bool]) -> "PlatformInfo":
        """
        Create a PlatformInfo object from a dictionary.

        Args:
            data: Dictionary mapping feature names to their enabled status

        Returns:
            New PlatformInfo object with the specified features
        """
        info = cls()
        info.smt_enabled = data.get("smt_enabled", False)
        info.tsme_enabled = data.get("tsme_enabled", False)
        info.ecc_enabled = data.get("ecc_enabled", False)
        info.rapl_disabled = data.get("rapl_disabled", False)
        info.ciphertext_hiding_enabled = data.get("ciphertext_hiding_enabled", False)
        info.alias_check_complete = data.get("alias_check_complete", False)
        info.tio_enabled = data.get("tio_enabled", False)
        return info

    def __repr__(self) -> str:
        """
        Get a string representation of the PlatformInfo object.

        Returns:
            String representation showing the raw value and enabled features
        """
        features = self.get_enabled_features()
        if features:
            feature_str = ", ".join(features)
            return f"PlatformInfo(0x{self._value:016x}, enabled=[{feature_str}])"
        else:
            return f"PlatformInfo(0x{self._value:016x}, enabled=[])"

    def __eq__(self, other) -> bool:
        """Check equality with another PlatformInfo object."""
        if not isinstance(other, PlatformInfo):
            return False
        return self._value == other._value

    def __hash__(self) -> int:
        """Return hash of the platform info value."""
        return hash(self._value)
