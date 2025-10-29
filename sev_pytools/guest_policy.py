# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# Guest policy management and validation for AMD SEV-SNP attestation.

from typing import Dict, List, Union


class GuestPolicy:
    """
    GuestPolicy - Represents the guest policy with various configurable options

    This class handles the guest policy flags found in AMD SEV-SNP attestation reports.
    The policy controls various security and operational aspects of the guest VM.

    Policy fields:
    - Bits 0-7: ABI minor version
    - Bits 8-15: ABI major version
    - Bit 16: SMT allowed
    - Bit 18: Migration MA allowed
    - Bit 19: Debug allowed
    - Bit 20: Single socket required
    - Bit 21: CXL allowed
    - Bit 22: Memory AES-256 XTS enabled
    - Bit 23: RAPL disabled
    - Bit 24: Ciphertext hiding enabled
    - Bit 25: Page swap disabled
    """

    def __init__(self, value: int = 0) -> None:
        """
        Initialize a GuestPolicy object.

        Args:
            value: The initial value of the policy (default: 0)
        """
        self._value = value

    @property
    def value(self) -> int:
        """Get the raw guest policy value."""
        return self._value

    @value.setter
    def value(self, val: int) -> None:
        """Set the raw guest policy value."""
        self._value = val

    def _get_bits(self, start: int, end: int) -> int:
        """
        Extract a range of bits from the policy value.

        Args:
            start: The starting bit position
            end: The ending bit position

        Returns:
            The extracted bit value
        """
        mask = ((1 << (end - start + 1)) - 1) << start
        return (self._value & mask) >> start

    def _set_bits(self, start: int, end: int, value: int) -> None:
        """
        Set a range of bits in the policy value.

        Args:
            start: The starting bit position
            end: The ending bit position
            value: The value to set
        """
        mask = ((1 << (end - start + 1)) - 1) << start
        self._value = (self._value & ~mask) | ((value << start) & mask)

    def _get_bit(self, position: int) -> bool:
        """
        Get the value of a specific bit in the policy value.

        Args:
            position: The bit position to check

        Returns:
            The value of the specified bit
        """
        return bool(self._value & (1 << position))

    def _set_bit(self, position: int, value: bool) -> None:
        """
        Set the value of a specific bit in the policy value.

        Args:
            position: The bit position to set
            value: The value to set (True for 1, False for 0)
        """
        if value:
            self._value |= 1 << position
        else:
            self._value &= ~(1 << position)

    @property
    def abi_minor(self) -> int:
        """
        Get the ABI minor version.

        Returns:
            The ABI minor version (0-255)
        """
        return self._get_bits(0, 7)

    @abi_minor.setter
    def abi_minor(self, value: int) -> None:
        """Set the ABI minor version."""
        self._set_bits(0, 7, value)

    @property
    def abi_major(self) -> int:
        """
        Get the ABI major version.

        Returns:
            The ABI major version (0-255)
        """
        return self._get_bits(8, 15)

    @abi_major.setter
    def abi_major(self, value: int) -> None:
        """Set the ABI major version."""
        self._set_bits(8, 15, value)

    @property
    def smt_allowed(self) -> bool:
        """
        Check if Simultaneous Multi-Threading (SMT) is allowed.

        When True, the guest VM is allowed to run on a processor with SMT enabled.
        When False, the guest requires SMT to be disabled for security reasons.

        Returns:
            True if SMT is allowed, False otherwise
        """
        return self._get_bit(16)

    @smt_allowed.setter
    def smt_allowed(self, value: bool) -> None:
        """Set whether SMT is allowed."""
        self._set_bit(16, value)

    @property
    def migrate_ma_allowed(self) -> bool:
        """
        Check if migration with Migration Agent (MA) is allowed.

        When True, the guest VM can be migrated to another system with
        Migration Agent assistance while maintaining security guarantees.

        Returns:
            True if migration MA is allowed, False otherwise
        """
        return self._get_bit(18)

    @migrate_ma_allowed.setter
    def migrate_ma_allowed(self, value: bool) -> None:
        """Set whether migration MA is allowed."""
        self._set_bit(18, value)

    @property
    def debug_allowed(self) -> bool:
        """
        Check if debugging is allowed.

        When True, debugging features can be used with this guest VM.
        When False, debugging is prohibited for security reasons.

        Returns:
            True if debugging is allowed, False otherwise
        """
        return self._get_bit(19)

    @debug_allowed.setter
    def debug_allowed(self, value: bool) -> None:
        """Set whether debugging is allowed."""
        self._set_bit(19, value)

    @property
    def single_socket_required(self) -> bool:
        """
        Check if a single socket is required.

        When True, the guest VM must run on a single CPU socket.
        This can be important for certain security or performance requirements.

        Returns:
            True if a single socket is required, False otherwise
        """
        return self._get_bit(20)

    @single_socket_required.setter
    def single_socket_required(self, value: bool) -> None:
        """Set whether a single socket is required."""
        self._set_bit(20, value)

    @property
    def cxl_allowed(self) -> bool:
        """
        Check if CXL (Compute Express Link) devices are allowed.

        When True, the guest VM can use CXL devices for enhanced I/O performance.

        Returns:
            True if CXL is allowed, False otherwise
        """
        return self._get_bit(21)

    @cxl_allowed.setter
    def cxl_allowed(self, value: bool) -> None:
        """Set whether CXL is allowed."""
        self._set_bit(21, value)

    @property
    def mem_aes_256_xts(self) -> bool:
        """
        Check if memory AES-256 XTS encryption is enabled.

        When True, memory is encrypted using AES-256 in XTS mode.

        Returns:
            True if memory AES-256 XTS is enabled, False otherwise
        """
        return self._get_bit(22)

    @mem_aes_256_xts.setter
    def mem_aes_256_xts(self, value: bool) -> None:
        """Set whether memory AES-256 XTS is enabled."""
        self._set_bit(22, value)

    @property
    def rapl_dis(self) -> bool:
        """
        Check if RAPL (Running Average Power Limit) is disabled.

        When True, RAPL interfaces are disabled to prevent power-based
        side-channel attacks.

        Returns:
            True if RAPL is disabled, False otherwise
        """
        return self._get_bit(23)

    @rapl_dis.setter
    def rapl_dis(self, value: bool) -> None:
        """Set whether RAPL is disabled."""
        self._set_bit(23, value)

    @property
    def ciphertext_hiding(self) -> bool:
        """
        Check if ciphertext hiding is enabled.

        When True, encrypted memory contents are obfuscated to prevent
        side-channel attacks based on memory access patterns.

        Returns:
            True if ciphertext hiding is enabled, False otherwise
        """
        return self._get_bit(24)

    @ciphertext_hiding.setter
    def ciphertext_hiding(self, value: bool) -> None:
        """Set whether ciphertext hiding is enabled."""
        self._set_bit(24, value)

    @property
    def page_swap_disable(self) -> bool:
        """
        Check if page swapping is disabled.

        Guest policy to disable Guest access to SNP_PAGE_MOVE,
        SNP_SWAP_OUT and SNP_SWAP_IN commands.

        When True, page swapping to disk is disabled for security reasons,
        preventing encrypted guest memory from being written to unencrypted storage.

        Returns:
            True if page swapping is disabled, False otherwise
        """
        return self._get_bit(25)

    @page_swap_disable.setter
    def page_swap_disable(self, value: bool) -> None:
        """Set whether page swapping is disabled."""
        self._set_bit(25, value)

    def get_enabled_features(self) -> List[str]:
        """
        Get a list of enabled policy features.

        Returns:
            List of feature names that are currently enabled
        """
        features = []
        features.append(f"ABI_{self.abi_major}.{self.abi_minor}")
        if self.smt_allowed:
            features.append("SMT_ALLOWED")
        if self.migrate_ma_allowed:
            features.append("MIGRATE_MA_ALLOWED")
        if self.debug_allowed:
            features.append("DEBUG_ALLOWED")
        if self.single_socket_required:
            features.append("SINGLE_SOCKET_REQUIRED")
        if self.cxl_allowed:
            features.append("CXL_ALLOWED")
        if self.mem_aes_256_xts:
            features.append("MEM_AES_256_XTS")
        if self.rapl_dis:
            features.append("RAPL_DISABLED")
        if self.ciphertext_hiding:
            features.append("CIPHERTEXT_HIDING")
        if self.page_swap_disable:
            features.append("PAGE_SWAP_DISABLED")
        return features

    def to_dict(self) -> Dict[str, Union[int, bool]]:
        """
        Convert guest policy to a dictionary.

        Returns:
            Dictionary mapping feature names to their values
        """
        return {
            "abi_major": self.abi_major,
            "abi_minor": self.abi_minor,
            "smt_allowed": self.smt_allowed,
            "migrate_ma_allowed": self.migrate_ma_allowed,
            "debug_allowed": self.debug_allowed,
            "single_socket_required": self.single_socket_required,
            "cxl_allowed": self.cxl_allowed,
            "mem_aes_256_xts": self.mem_aes_256_xts,
            "rapl_dis": self.rapl_dis,
            "ciphertext_hiding": self.ciphertext_hiding,
            "page_swap_disable": self.page_swap_disable,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Union[int, bool]]) -> "GuestPolicy":
        """
        Create a GuestPolicy object from a dictionary.

        Args:
            data: Dictionary mapping feature names to their values

        Returns:
            New GuestPolicy object with the specified features
        """
        policy = cls()
        policy.abi_major = data.get("abi_major", 0)
        policy.abi_minor = data.get("abi_minor", 0)
        policy.smt_allowed = data.get("smt_allowed", False)
        policy.migrate_ma_allowed = data.get("migrate_ma_allowed", False)
        policy.debug_allowed = data.get("debug_allowed", False)
        policy.single_socket_required = data.get("single_socket_required", False)
        policy.cxl_allowed = data.get("cxl_allowed", False)
        policy.mem_aes_256_xts = data.get("mem_aes_256_xts", False)
        policy.rapl_dis = data.get("rapl_dis", False)
        policy.ciphertext_hiding = data.get("ciphertext_hiding", False)
        policy.page_swap_disable = data.get("page_swap_disable", False)
        return policy

    def __repr__(self) -> str:
        """
        Get a string representation of the GuestPolicy object.

        Returns:
            String representation showing the raw value and enabled features
        """
        features = self.get_enabled_features()
        feature_str = ", ".join(features)
        return f"GuestPolicy(0x{self._value:016x}, features=[{feature_str}])"

    def __eq__(self, other) -> bool:
        """Check equality with another GuestPolicy object."""
        if not isinstance(other, GuestPolicy):
            return False
        return self._value == other._value

    def __hash__(self) -> int:
        """Return hash of the guest policy value."""
        return hash(self._value)
