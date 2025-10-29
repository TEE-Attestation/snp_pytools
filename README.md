# sev_pytools

sev_pytools is a Python-based tool for verifying AMD SEV-SNP (Secure Encrypted Virtualization - Secure Nested Paging) attestation reports. This project provides functionality to parse, print, and verify attestation reports against a chain of certificates, and fetch certificates from the AMD Key Distribution Service (KDS).

## Project Structure

The project consists of the following main components:

1. `attestation_report.py`: Defines the `AttestationReport` class for parsing and representing attestation reports, along with the `TcbVersion` and `Cpuid` dataclasses.
2. `certs.py`: Handles certificate loading, verification, and printing.
3. `guest_policy.py`: Defines the `GuestPolicy` class for managing guest policy information.
4. `platform_info.py`: Defines the `PlatformInfo` class for managing platform information.
5. `signature.py`: Defines the `Signature` class for handling cryptographic signatures.
6. `policy.py`: Provides the `AttestationPolicy` class for validating attestation reports against security policies.
7. `print_report.py`: Command-line tool for printing attestation report details.
8. `verify.py`: Main verification script that checks the attestation report against the certificate chain.
9. `fetch.py`: Tool for fetching certificates (ARK, ASK, VCEK) from the AMD Key Distribution Service.

## Usage

### Printing an Attestation Report

To print the details of an attestation report:

```
python print_report.py -f path/to/report.bin [-d]
```
or if installed with pip use `sev-print ...`.

- `-f` or `--file`: Path to the attestation report file (default: report.bin)
- `-d` or `--debug`: Enable debug mode for additional output

### Verifying an Attestation Report

To verify an attestation report against a certificate chain and optionally a policy:

```
python verify.py -f path/to/report.bin -c path/to/certs/directory [-d] [-v]
```
or if installed with pip use `sev-verify ...`.

- `-f` or `--file`: Path to the attestation report file (default: report.bin)
- `-c` or `--certs`: Path to the directory containing certificates (default: ca)
- `-d` or `--debug`: Enable debug mode for additional output (automatically enables verbose mode)
- `-v` or `--verbose`: Enable verbose mode for detailed information
- `-r` or `--reportdata`: Print report data at the end of successful verification
- `-p` or `--processor`: Processor model (e.g., milan, genoa) used only if no certificates found (default: genoa)
- `-q` or `--policy`: Path to the policy file for validating the report against security policies (optional)

### Policy Validation

The toolkit supports validating attestation reports against security policies defined in JSON format. This allows you to enforce specific security requirements and check measurements are known good values.

#### Policy File Format

Policies are defined in JSON format with the following structure:

```json
{
  "metadata": {
    "name": "AMD SEV-SNP Security Policy",
    "version": "1.0",
    "description": "Example security policy for validating AMD SEV-SNP attestation reports"
  },
  "validation_rules": {
    "measurement": {
      "exact_match": "123456789abcdef..."
    },
    "version": {
      "min_value": 3
    },
    "policy": {
      "migrate_ma_allowed": false,
      "debug_allowed": false
    },
    "platform_info": {
      "tsme_enabled": true,
      "alias_check_complete": true
    },
    "current_tcb": {
      "bootloader": {
        "min_value": 9
      },
      "tee": {
        "min_value": 0
      },
      "snp": {
        "min_value": 15
      },
      "microcode": {
        "min_value": 72
      }
    }
  }
}
```

#### Policy Validation Rules

The following validation rule types are supported:

- **exact_match**: Field must exactly match the specified value
- **min_value**: Field must be greater than or equal to the specified minimum
- **max_value**: Field must be less than or equal to the specified maximum
- **allow_list**: Field value must be in the list of allowed values
- **deny_list**: Field value must not be in the list of denied values
- **boolean**: Field must match the specified boolean value (true/false). This can be specified using the boolean value as the attribute value directly.

#### Using Policy Validation

Policy validation can be used programmatically:

```python
from sev_pytools import AttestationPolicy, AttestationReport

# Load policy from file
policy = AttestationPolicy(policy_file="policy.json")

# Load attestation report
report = AttestationReport.from_file("report.bin")

# Validate report against policy
try:
    policy.validate_report(report, verbose=True)
    print("Report passed all policy checks!")
except PolicyValidationError as e:
    print(f"Policy validation failed: {e}")
```

The `verify.py` script also supports policy validation when the `-q` or `--policy` flag is used with a policy file path:

```
python verify.py -f path/to/report.bin -c path/to/certs/directory -q path/to/policy.json [-v]
```

This will perform both cryptographic verification of the attestation report and validate it against the specified policy file.

### Fetching Certificates

To fetch certificates from the AMD Key Distribution Service:

```
python fetch.py ca -p PROCESSOR -e ENCODING -d DIRECTORY [--endorser {vcek,vlek}]
python fetch.py vcek -p PROCESSOR -e ENCODING -d DIRECTORY -r REPORT_PATH
```
or if installed with pip use `sev-fetch ...`.

- `ca`: Fetch ARK and ASK certificates
- `vcek`: Fetch VCEK certificate
- `-p` or `--processor`: Processor model (e.g., milan, genoa) (default: genoa)
- `-e` or `--encoding`: Certificate encoding format (PEM or DER)
- `-d` or `--directory`: Directory to save the fetched certificates
- `--endorser`: Endorser type (vcek or vlek) for fetching VCEK or VLEK certificates
- `-r` or `--report`: Path to the attestation report file (required for fetching VCEK)

## Logging

SNP PyTools includes comprehensive logging support for both library usage and command-line tools. This helps with debugging, monitoring, and auditing.

### Command Line Logging

All command-line tools support logging flags.
Available logging options:
- `-v, --verbose`: Enable verbose logging (shows DEBUG level messages)
- `-q, --quiet`: Enable quiet mode (only WARNING and ERROR messages)
- `--log-file PATH`: Write logs to specified file in addition to console output

```bash
# Enable verbose logging (DEBUG level)
sev-verify -f report.bin --verbose

# Enable quiet mode (WARNING level and above)
sev-fetch ca --quiet

# Save logs to file
sev-print -f report.bin --log-file verification.log
```



### Library Logging

When using sev_pytools as a library, you can configure logging to suit your application:

```python
from sev_pytools import setup_library_logging, get_logger, AttestationReport

# Setup logging for library usage
logger = setup_library_logging(level="INFO", log_file="snp_operations.log")

# Use the logger
logger.info("Starting attestation report processing")

# Load and process a report - the library will automatically log key operations
with open("report.bin", "rb") as f:
    data = f.read()

report = AttestationReport.unpack(data)  # This will log parsing progress
logger.info("Successfully parsed attestation report")
```

## Requirements

- Python 3.6+
- cryptography library >= 39.0.0
- requests library

## Installation

1. Clone the repository
2. Move into root directory and install
   ```
   pip install .
   ```

## Uninstallation
1. Run pip uninstall
   ```
   pip uninstall sev_pytools
   ```

## Acknowledgments

This project is based on the AMD SEV-SNP specification and related documentation.
All the specifications used can be found here: [https://www.amd.com/en/developer/sev.html](https://www.amd.com/en/developer/sev.html)

The snpguest rust tool that can be used to generate the attestation report, and that models the verification process, can be found here: [https://github.com/virtee/snpguest/tree/main](https://github.com/virtee/snpguest/tree/main)

## License

MIT License - Copyright 2025 Hewlett Packard Enterprise Development LP.

See [LICENSE](LICENSE) file for details.