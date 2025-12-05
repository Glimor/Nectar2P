# Changelog

All notable changes to this project will be documented in this file.

## [1.2.0] - 2024-12-05

### Security
- **CRITICAL**: Added MITM attack protection with public key verification
- **CRITICAL**: Added path traversal protection to prevent unauthorized file access
- **CRITICAL**: Added DoS protection with timeouts, buffer limits, and file size limits
- Added replay attack protection with nonce reuse detection
- Replaced `random` with `secrets` module for cryptographically secure randomness
- Improved error messages to prevent information leakage

### Added
- New `export-key` command to export public keys for verification
- `--verify-key` parameter for both send and receive commands
- Connection timeout (30 seconds)
- Socket buffer limits (1MB send/receive)
- File size limit (10GB)
- Input validation for ports, file sizes, and offsets

### Changed
- Connection limit reduced to 1 concurrent connection
- Error messages are now generic to improve security
- Improved socket configuration with SO_REUSEADDR

### Fixed
- Potential integer overflow in file size handling
- Missing validation on resume offset
- Unsafe random number generation in STUN protocol

## [1.1.0] - Previous Release

### Added
- Initial release with P2P file transfer
- RSA and AES-GCM encryption
- NAT traversal support
- Resume capability
- SHA-256 integrity verification
