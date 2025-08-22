# PSCryptor

A comprehensive PowerShell module for encrypting and decrypting strings or byte arrays using various .NET cryptographic algorithms. Supports both Pre-Shared Key (PSK) and certificate-based encryption methods.

## Features

- **Multiple Algorithms**: AES, DES, TripleDES, and RSA encryption
- **Flexible Input**: Support for both strings and byte arrays
- **Key Management**: PSK-based encryption with PBKDF2 key derivation
- **Certificate Support**: RSA encryption/decryption using X.509 certificates
- **Secure Defaults**: Uses industry-standard practices (AES-256, PBKDF2, random salts/IVs)
- **Pipeline Support**: All functions support PowerShell pipeline operations
- **Comprehensive Testing**: Built-in test functions and validation

## Installation

1. Clone or download this repository
2. Import the module:
   ```powershell
   Import-Module "C:\Path\To\PSCryptor\PSCryptor.psd1"
   ```

Or copy the module to your PowerShell modules directory:
```powershell
$ModulePath = "$env:USERPROFILE\Documents\PowerShell\Modules\PSCryptor"
# Copy the PSCryptor folder to $ModulePath
Import-Module PSCryptor
```

## Quick Start

### Basic String Encryption (AES)
```powershell
# Import the module
Import-Module PSCryptor

# Encrypt a string
$encrypted = Protect-String -PlainText "My secret message" -Algorithm AES -Password "MySecurePassword"

# Decrypt the string
$decrypted = Unprotect-String -EncryptedData $encrypted -Algorithm AES -Password "MySecurePassword"

Write-Output $decrypted  # "My secret message"
```

### Certificate-based Encryption (RSA)
```powershell
# Get a certificate with private key
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.HasPrivateKey } | Select-Object -First 1

# Encrypt with certificate
$encrypted = Protect-String -PlainText "Secret data" -Algorithm RSA -Certificate $cert

# Decrypt with certificate
$decrypted = Unprotect-String -EncryptedData $encrypted -Algorithm RSA -Certificate $cert
```

## Available Functions

### Core Functions

- **`Protect-String`** - Encrypts a plain text string
- **`Unprotect-String`** - Decrypts an encrypted string
- **`Protect-ByteArray`** - Encrypts a byte array
- **`Unprotect-ByteArray`** - Decrypts an encrypted byte array

### Utility Functions

- **`New-CryptographyKey`** - Generates random cryptographic keys
- **`Get-SupportedAlgorithms`** - Lists available algorithms and their properties
- **`Test-CryptographyProvider`** - Runs validation tests on the module

## Supported Algorithms

| Algorithm | Type | Key Sizes | Recommended | Notes |
|-----------|------|-----------|-------------|-------|
| AES | Symmetric | 128, 192, 256 bits | ✅ Yes | Best performance and security |
| TripleDES | Symmetric | 128, 192 bits | ⚠️ Legacy | Slower than AES |
| DES | Symmetric | 64 bits | ❌ No | Deprecated, weak security |
| RSA | Asymmetric | 1024, 2048, 4096 bits | ✅ Yes | Certificate-based encryption |

## Usage Examples

### String Encryption with Different Algorithms
```powershell
$plainText = "Sensitive information"
$password = "StrongPassword123!"

# AES encryption (recommended)
$aesEncrypted = Protect-String -PlainText $plainText -Algorithm AES -Password $password -KeySize 256

# TripleDES encryption
$tripleDesEncrypted = Protect-String -PlainText $plainText -Algorithm TripleDES -Password $password

# Decrypt
$aesDecrypted = Unprotect-String -EncryptedData $aesEncrypted -Algorithm AES -Password $password
$tripleDesDecrypted = Unprotect-String -EncryptedData $tripleDesEncrypted -Algorithm TripleDES -Password $password
```

### Byte Array Encryption
```powershell
# Encrypt binary data
$data = [System.IO.File]::ReadAllBytes("C:\path\to\file.bin")
$encrypted = Protect-ByteArray -Data $data -Algorithm AES -Password "FilePassword"

# Decrypt binary data
$decrypted = Unprotect-ByteArray -EncryptedData $encrypted -Algorithm AES -Password "FilePassword"
[System.IO.File]::WriteAllBytes("C:\path\to\decrypted.bin", $decrypted)
```

### Pipeline Operations
```powershell
# Encrypt multiple strings
$secrets = @("Secret1", "Secret2", "Secret3")
$encryptedSecrets = $secrets | ForEach-Object { 
    Protect-String -PlainText $_ -Algorithm AES -Password "BatchPassword" 
}

# Decrypt multiple strings
$decryptedSecrets = $encryptedSecrets | ForEach-Object { 
    Unprotect-String -EncryptedData $_ -Algorithm AES -Password "BatchPassword" 
}
```

### Custom Salt and Key Generation
```powershell
# Generate a random key
$key = New-CryptographyKey -Algorithm AES -KeySize 256 -AsBase64

# Use custom salt
$customSalt = [System.Text.Encoding]::UTF8.GetBytes("MyCustomSalt12345")
$encrypted = Protect-String -PlainText "Data" -Algorithm AES -Password "Password" -Salt $customSalt
```

### Certificate Management
```powershell
# Create a self-signed certificate for testing
$cert = New-SelfSignedCertificate -Subject "CN=PSCryptorTest" -KeyUsage DigitalSignature,KeyEncipherment -Type DocumentEncryptionCert -CertStoreLocation Cert:\CurrentUser\My

# Use certificate for encryption
$encrypted = Protect-String -PlainText "Certificate protected data" -Algorithm RSA -Certificate $cert
$decrypted = Unprotect-String -EncryptedData $encrypted -Algorithm RSA -Certificate $cert

# Clean up
Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -Force
```

## Security Considerations

### Best Practices

1. **Use AES-256** for symmetric encryption (default in this module)
2. **Use strong passwords** with sufficient entropy
3. **Protect your certificates** and private keys
4. **Use PBKDF2** for password-based key derivation (automatically used)
5. **Random salts and IVs** are generated automatically
6. **Secure key storage** - consider using Windows DPAPI or Azure Key Vault for production

### Security Features

- **PBKDF2 Key Derivation**: Uses 10,000 iterations with SHA-256
- **Random Salt Generation**: 16-byte cryptographically secure random salts
- **Automatic IV Generation**: Unique initialization vectors for each encryption
- **Secure Padding**: PKCS7 padding for block ciphers
- **Certificate Validation**: Validates certificate capabilities before use

## Testing

Run the comprehensive test suite:
```powershell
# Test all algorithms
Test-CryptographyProvider

# Test specific algorithm with detailed output
Test-CryptographyProvider -Algorithm AES -Detailed

# Run the full test suite
.\Tests\Test-PSCryptor.ps1
```

Run example scripts:
```powershell
# Basic string encryption examples
.\Examples\BasicStringEncryption.ps1

# Certificate-based encryption examples
.\Examples\CertificateEncryption.ps1
```

## Module Structure

```
PSCryptor/
├── PSCryptor.psd1              # Module manifest
├── PSCryptor.psm1              # Main module file
├── Classes/
│   └── CryptographyProvider.psm1  # Core cryptography class
├── Examples/
│   ├── README.md               # Example documentation
│   ├── BasicStringEncryption.ps1
│   └── CertificateEncryption.ps1
├── Tests/
│   └── Test-PSCryptor.ps1      # Test suite
└── README.md                   # This file
```

## Error Handling

The module provides comprehensive error handling:

- **Invalid algorithms** throw descriptive errors
- **Wrong passwords** result in decryption failures
- **Certificate issues** are clearly reported
- **Key size validation** prevents invalid configurations
- **Algorithm mismatches** are detected and reported

## Performance

Performance characteristics vary by algorithm:

- **AES**: Fastest symmetric encryption, recommended for most use cases
- **TripleDES**: ~3x slower than AES, legacy compatibility
- **DES**: Fastest but insecure, not recommended
- **RSA**: Slowest, suitable for small data or key exchange

## Requirements

- **PowerShell 5.1** or higher
- **.NET Framework 4.7.2** or higher
- **Windows PowerShell** or **PowerShell Core/7+**

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Changelog

### Version 1.0.0 (2025-08-22)
- Initial release
- Support for AES, DES, TripleDES, and RSA algorithms
- PSK and certificate-based encryption
- Comprehensive test suite
- Example scripts and documentation

## Support

For issues, questions, or contributions, please use the GitHub repository issue tracker.
