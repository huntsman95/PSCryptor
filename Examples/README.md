# PSCryptor Module Examples

This directory contains example scripts demonstrating how to use the PSCryptor module.

## Basic Examples

### 1. String Encryption with AES
```powershell
# Import the module
Import-Module PSCryptor

# Encrypt a string
$plainText = "This is my secret message"
$password = "MySecretPassword123!"
$encrypted = Protect-String -PlainText $plainText -Algorithm AES -Password $password

# Decrypt the string
$decrypted = Unprotect-String -EncryptedData $encrypted -Algorithm AES -Password $password
Write-Output "Original: $plainText"
Write-Output "Decrypted: $decrypted"
```

### 2. Byte Array Encryption
```powershell
# Encrypt a byte array
$data = [System.Text.Encoding]::UTF8.GetBytes("Secret data")
$encrypted = Protect-ByteArray -Data $data -Algorithm AES -Password "MyPassword"

# Decrypt the byte array
$decrypted = Unprotect-ByteArray -EncryptedData $encrypted -Algorithm AES -Password "MyPassword"
$decryptedString = [System.Text.Encoding]::UTF8.GetString($decrypted)
```

### 3. Certificate-based Encryption (RSA)
```powershell
# Find a certificate with a private key
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { 
    $_.HasPrivateKey -and $_.Subject -like "*YourName*" 
} | Select-Object -First 1

if ($cert) {
    # Encrypt with certificate
    $encrypted = Protect-String -PlainText "Secret message" -Algorithm RSA -Certificate $cert
    
    # Decrypt with certificate
    $decrypted = Unprotect-String -EncryptedData $encrypted -Algorithm RSA -Certificate $cert
}
```

### 4. Key Generation
```powershell
# Generate a random key for AES
$key = New-CryptographyKey -Algorithm AES -KeySize 256
$keyBase64 = New-CryptographyKey -Algorithm AES -AsBase64
```

### 5. Testing the Module
```powershell
# Test all algorithms
Test-CryptographyProvider

# Test a specific algorithm with detailed results
Test-CryptographyProvider -Algorithm AES -Detailed

# Get supported algorithms
Get-SupportedAlgorithms
```

## Advanced Examples

See the individual example files in this directory for more detailed usage scenarios.
