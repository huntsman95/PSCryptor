#Requires -Version 5.1

<#
.SYNOPSIS
    PSCryptor - A comprehensive PowerShell module for encryption and decryption
    
.DESCRIPTION
    PSCryptor provides a set of functions to encrypt and decrypt strings or byte arrays
    using various .NET cryptographic algorithms. Supports both Pre-Shared Key (PSK) and
    certificate-based encryption methods.
    
.NOTES
    Name:           PSCryptor
    Author:         PSCryptor Team
    Version:        1.0.0
    DateCreated:    August 22, 2025
    
.EXAMPLE
    Import-Module PSCryptor
    $encrypted = Protect-String -PlainText "Hello World" -Algorithm AES -Password "MySecretKey"
    $decrypted = Unprotect-String -EncryptedData $encrypted -Algorithm AES -Password "MySecretKey"
#>

using namespace System.Security.Cryptography
using namespace System.Security.Cryptography.X509Certificates
using namespace System.Text
using namespace System.IO

# Load the cryptography provider class
. (Join-Path $PSScriptRoot "Classes\CryptographyProvider.ps1")

# Create a module-level provider instance
$script:CryptoProvider = [CryptographyProvider]::new()

#region Public Functions

<#
.SYNOPSIS
    Encrypts a plain text string using the specified algorithm and key.
    
.DESCRIPTION
    Protect-String encrypts a plain text string using various cryptographic algorithms
    including AES, DES, TripleDES with PSK or RSA with certificates.
    
.PARAMETER PlainText
    The plain text string to encrypt.
    
.PARAMETER Algorithm
    The encryption algorithm to use (AES, DES, TripleDES, RSA).
    
.PARAMETER Password
    The password/key for symmetric encryption algorithms.
    
.PARAMETER Certificate
    The X509Certificate2 object for RSA encryption.
    
.PARAMETER CertificatePath
    Path to the certificate file for RSA encryption.
    
.PARAMETER KeySize
    The key size for the encryption algorithm (optional).
    
.PARAMETER Salt
    Custom salt for key derivation (optional).
    
.EXAMPLE
    $encrypted = Protect-String -PlainText "Secret Message" -Algorithm AES -Password "MyPassword123"
    
.EXAMPLE
    $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*MyCompany*" }
    $encrypted = Protect-String -PlainText "Secret Message" -Algorithm RSA -Certificate $cert
#>
function Protect-String {
    [CmdletBinding(DefaultParameterSetName = 'PSK')]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$PlainText,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('AES', 'DES', 'TripleDES', 'RSA')]
        [string]$Algorithm,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'PSK')]
        [string]$Password,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'CertificatePath')]
        [string]$CertificatePath,
        
        [Parameter()]
        [int]$KeySize,
        
        [Parameter()]
        [byte[]]$Salt
    )
    
    try {
        if ($PSCmdlet.ParameterSetName -eq 'PSK') {
            $result = $script:CryptoProvider.EncryptString($PlainText, $Algorithm, $Password, $KeySize, $Salt)
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'Certificate') {
            $result = $script:CryptoProvider.EncryptString($PlainText, $Algorithm, $Certificate)
        }
        else {
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificatePath)
            $result = $script:CryptoProvider.EncryptString($PlainText, $Algorithm, $cert)
        }
        
        return $result
    }
    catch {
        Write-Error "Failed to encrypt string: $($_.Exception.Message)"
        return $null
    }
}

<#
.SYNOPSIS
    Decrypts a string that was encrypted using Protect-String.
    
.DESCRIPTION
    Unprotect-String decrypts strings that were encrypted using various algorithms.
    Can accept either an EncryptedData object (from Protect-String) or individual 
    parameters for more flexibility.
    
.PARAMETER EncryptedData
    The encrypted data object returned by Protect-String (for object-based decryption).
    
.PARAMETER EncryptedString
    The base64-encoded encrypted string (for parameter-based decryption).
    
.PARAMETER Algorithm
    The encryption algorithm used (AES, DES, TripleDES, RSA).
    When using EncryptedData object, this can be omitted as it's read from the object.
    
.PARAMETER Password
    The password/key used for symmetric encryption algorithms.
    
.PARAMETER Certificate
    The X509Certificate2 object with private key for RSA decryption.
    
.PARAMETER CertificatePath
    Path to the certificate file for RSA decryption.
    
.PARAMETER InitializationVector
    The initialization vector (base64-encoded) used during encryption.
    Required for parameter-based symmetric decryption.
    
.PARAMETER Salt
    The salt (base64-encoded) used for key derivation.
    Required for parameter-based symmetric decryption.
    
.PARAMETER KeySize
    The key size used during encryption.
    Required for parameter-based symmetric decryption.
    
.EXAMPLE
    # Object-based decryption (current method)
    $encrypted = Protect-String -PlainText "Secret" -Algorithm AES -Password "MyPassword123"
    $decrypted = Unprotect-String -EncryptedData $encrypted -Algorithm AES -Password "MyPassword123"
    
.EXAMPLE
    # Parameter-based decryption (new method)
    $decrypted = Unprotect-String -EncryptedString "base64string..." -Algorithm AES -Password "MyPassword123" -InitializationVector "base64iv..." -Salt "base64salt..." -KeySize 256
    
.EXAMPLE
    # Certificate-based decryption
    $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*MyCompany*" -and $_.HasPrivateKey }
    $decrypted = Unprotect-String -EncryptedData $encrypted -Certificate $cert
#>
function Unprotect-String {
    [CmdletBinding(DefaultParameterSetName = 'ObjectPSK')]
    param(
        # Object-based parameters
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'ObjectPSK')]
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'ObjectCertificate')]
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'ObjectCertificatePath')]
        [PSCustomObject]$EncryptedData,
        
        # Parameter-based parameters
        [Parameter(Mandatory = $true, ParameterSetName = 'ParameterPSK')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ParameterCertificate')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ParameterCertificatePath')]
        [string]$EncryptedString,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'ParameterPSK')]
        [Parameter(ParameterSetName = 'ParameterCertificate')]
        [Parameter(ParameterSetName = 'ParameterCertificatePath')]
        [string]$InitializationVector,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'ParameterPSK')]
        [string]$Salt,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'ParameterPSK')]
        [int]$KeySize,
        
        # Algorithm (optional for object-based, required for parameter-based)
        [Parameter(ParameterSetName = 'ObjectPSK')]
        [Parameter(ParameterSetName = 'ObjectCertificate')]
        [Parameter(ParameterSetName = 'ObjectCertificatePath')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ParameterPSK')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ParameterCertificate')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ParameterCertificatePath')]
        [ValidateSet('AES', 'DES', 'TripleDES', 'RSA')]
        [string]$Algorithm,
        
        # Authentication parameters
        [Parameter(Mandatory = $true, ParameterSetName = 'ObjectPSK')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ParameterPSK')]
        [string]$Password,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'ObjectCertificate')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ParameterCertificate')]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'ObjectCertificatePath')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ParameterCertificatePath')]
        [string]$CertificatePath
    )
    
    try {
        # Determine if we're using object-based or parameter-based approach
        if ($PSCmdlet.ParameterSetName -like 'Object*') {
            # Object-based approach (current method)
            $actualAlgorithm = if ($Algorithm) { $Algorithm } else { $EncryptedData.Algorithm }
            
            if ($PSCmdlet.ParameterSetName -eq 'ObjectPSK') {
                $result = $script:CryptoProvider.DecryptString($EncryptedData, $actualAlgorithm, $Password)
            }
            elseif ($PSCmdlet.ParameterSetName -eq 'ObjectCertificate') {
                $result = $script:CryptoProvider.DecryptString($EncryptedData, $actualAlgorithm, $Certificate)
            }
            else {
                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificatePath)
                $result = $script:CryptoProvider.DecryptString($EncryptedData, $actualAlgorithm, $cert)
            }
        }
        else {
            # Parameter-based approach (new method)
            if ($PSCmdlet.ParameterSetName -eq 'ParameterPSK') {
                # Create encrypted data object from parameters
                $encryptedDataObj = [PSCustomObject]@{
                    Algorithm = $Algorithm
                    KeySize   = $KeySize
                    IV        = $InitializationVector
                    Salt      = $Salt
                    Data      = $EncryptedString
                    Timestamp = $null
                }
                $result = $script:CryptoProvider.DecryptString($encryptedDataObj, $Algorithm, $Password)
            }
            elseif ($PSCmdlet.ParameterSetName -eq 'ParameterCertificate') {
                # Create encrypted data object for RSA
                $encryptedDataObj = [PSCustomObject]@{
                    Algorithm             = $Algorithm
                    KeySize               = $null
                    Data                  = $EncryptedString
                    CertificateThumbprint = $Certificate.Thumbprint
                    Timestamp             = $null
                }
                $result = $script:CryptoProvider.DecryptString($encryptedDataObj, $Algorithm, $Certificate)
            }
            else {
                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificatePath)
                $encryptedDataObj = [PSCustomObject]@{
                    Algorithm             = $Algorithm
                    KeySize               = $null
                    Data                  = $EncryptedString
                    CertificateThumbprint = $cert.Thumbprint
                    Timestamp             = $null
                }
                $result = $script:CryptoProvider.DecryptString($encryptedDataObj, $Algorithm, $cert)
            }
        }
        
        return $result
    }
    catch {
        Write-Error "Failed to decrypt string: $($_.Exception.Message)"
        return $null
    }
}

<#
.SYNOPSIS
    Encrypts a byte array using the specified algorithm and key.
    
.DESCRIPTION
    Protect-ByteArray encrypts a byte array using various cryptographic algorithms.
    
.PARAMETER Data
    The byte array to encrypt.
    
.PARAMETER Algorithm
    The encryption algorithm to use (AES, DES, TripleDES, RSA).
    
.PARAMETER Password
    The password/key for symmetric encryption algorithms.
    
.PARAMETER Certificate
    The X509Certificate2 object for RSA encryption.
    
.PARAMETER CertificatePath
    Path to the certificate file for RSA encryption.
    
.PARAMETER KeySize
    The key size for the encryption algorithm (optional).
    
.PARAMETER Salt
    Custom salt for key derivation (optional).
    
.EXAMPLE
    $data = [System.Text.Encoding]::UTF8.GetBytes("Secret Message")
    $encrypted = Protect-ByteArray -Data $data -Algorithm AES -Password "MyPassword123"
#>
function Protect-ByteArray {
    [CmdletBinding(DefaultParameterSetName = 'PSK')]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [byte[]]$Data,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('AES', 'DES', 'TripleDES', 'RSA')]
        [string]$Algorithm,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'PSK')]
        [string]$Password,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'CertificatePath')]
        [string]$CertificatePath,
        
        [Parameter()]
        [int]$KeySize,
        
        [Parameter()]
        [byte[]]$Salt
    )
    
    try {
        if ($PSCmdlet.ParameterSetName -eq 'PSK') {
            $result = $script:CryptoProvider.EncryptBytes($Data, $Algorithm, $Password, $KeySize, $Salt)
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'Certificate') {
            $result = $script:CryptoProvider.EncryptBytes($Data, $Algorithm, $Certificate)
        }
        else {
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificatePath)
            $result = $script:CryptoProvider.EncryptBytes($Data, $Algorithm, $cert)
        }
        
        return $result
    }
    catch {
        Write-Error "Failed to encrypt byte array: $($_.Exception.Message)"
        return $null
    }
}

<#
.SYNOPSIS
    Decrypts a byte array that was encrypted using Protect-ByteArray.
    
.DESCRIPTION
    Unprotect-ByteArray decrypts byte arrays that were encrypted using various algorithms.
    Can accept either an EncryptedData object (from Protect-ByteArray) or individual 
    parameters for more flexibility.
    
.PARAMETER EncryptedData
    The encrypted data object returned by Protect-ByteArray (for object-based decryption).
    
.PARAMETER EncryptedString
    The base64-encoded encrypted data (for parameter-based decryption).
    
.PARAMETER Algorithm
    The encryption algorithm used (AES, DES, TripleDES, RSA).
    When using EncryptedData object, this can be omitted as it's read from the object.
    
.PARAMETER Password
    The password/key used for symmetric encryption algorithms.
    
.PARAMETER Certificate
    The X509Certificate2 object with private key for RSA decryption.
    
.PARAMETER CertificatePath
    Path to the certificate file for RSA decryption.
    
.PARAMETER InitializationVector
    The initialization vector (base64-encoded) used during encryption.
    Required for parameter-based symmetric decryption.
    
.PARAMETER Salt
    The salt (base64-encoded) used for key derivation.
    Required for parameter-based symmetric decryption.
    
.PARAMETER KeySize
    The key size used during encryption.
    Required for parameter-based symmetric decryption.
    
.EXAMPLE
    # Object-based decryption (current method)
    $data = [System.Text.Encoding]::UTF8.GetBytes("Secret Message")
    $encrypted = Protect-ByteArray -Data $data -Algorithm AES -Password "MyPassword123"
    $decrypted = Unprotect-ByteArray -EncryptedData $encrypted -Password "MyPassword123"
    
.EXAMPLE
    # Parameter-based decryption (new method)
    $decrypted = Unprotect-ByteArray -EncryptedString "base64data..." -Algorithm AES -Password "MyPassword123" -InitializationVector "base64iv..." -Salt "base64salt..." -KeySize 256
    
.EXAMPLE
    # Certificate-based decryption
    $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*MyCompany*" -and $_.HasPrivateKey }
    $decrypted = Unprotect-ByteArray -EncryptedData $encrypted -Certificate $cert
#>
function Unprotect-ByteArray {
    [CmdletBinding(DefaultParameterSetName = 'ObjectPSK')]
    param(
        # Object-based parameters
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'ObjectPSK')]
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'ObjectCertificate')]
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'ObjectCertificatePath')]
        [PSCustomObject]$EncryptedData,
        
        # Parameter-based parameters
        [Parameter(Mandatory = $true, ParameterSetName = 'ParameterPSK')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ParameterCertificate')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ParameterCertificatePath')]
        [string]$EncryptedString,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'ParameterPSK')]
        [Parameter(ParameterSetName = 'ParameterCertificate')]
        [Parameter(ParameterSetName = 'ParameterCertificatePath')]
        [string]$InitializationVector,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'ParameterPSK')]
        [string]$Salt,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'ParameterPSK')]
        [int]$KeySize,
        
        # Algorithm (optional for object-based, required for parameter-based)
        [Parameter(ParameterSetName = 'ObjectPSK')]
        [Parameter(ParameterSetName = 'ObjectCertificate')]
        [Parameter(ParameterSetName = 'ObjectCertificatePath')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ParameterPSK')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ParameterCertificate')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ParameterCertificatePath')]
        [ValidateSet('AES', 'DES', 'TripleDES', 'RSA')]
        [string]$Algorithm,
        
        # Authentication parameters
        [Parameter(Mandatory = $true, ParameterSetName = 'ObjectPSK')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ParameterPSK')]
        [string]$Password,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'ObjectCertificate')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ParameterCertificate')]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'ObjectCertificatePath')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ParameterCertificatePath')]
        [string]$CertificatePath
    )
    
    try {
        # Determine if we're using object-based or parameter-based approach
        if ($PSCmdlet.ParameterSetName -like 'Object*') {
            # Object-based approach (current method)
            $actualAlgorithm = if ($Algorithm) { $Algorithm } else { $EncryptedData.Algorithm }
            
            if ($PSCmdlet.ParameterSetName -eq 'ObjectPSK') {
                $result = $script:CryptoProvider.DecryptBytes($EncryptedData, $actualAlgorithm, $Password)
            }
            elseif ($PSCmdlet.ParameterSetName -eq 'ObjectCertificate') {
                $result = $script:CryptoProvider.DecryptBytes($EncryptedData, $actualAlgorithm, $Certificate)
            }
            else {
                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificatePath)
                $result = $script:CryptoProvider.DecryptBytes($EncryptedData, $actualAlgorithm, $cert)
            }
        }
        else {
            # Parameter-based approach (new method)
            if ($PSCmdlet.ParameterSetName -eq 'ParameterPSK') {
                # Create encrypted data object from parameters
                $encryptedDataObj = [PSCustomObject]@{
                    Algorithm = $Algorithm
                    KeySize   = $KeySize
                    IV        = $InitializationVector
                    Salt      = $Salt
                    Data      = $EncryptedString
                    Timestamp = $null
                }
                $result = $script:CryptoProvider.DecryptBytes($encryptedDataObj, $Algorithm, $Password)
            }
            elseif ($PSCmdlet.ParameterSetName -eq 'ParameterCertificate') {
                # Create encrypted data object for RSA
                $encryptedDataObj = [PSCustomObject]@{
                    Algorithm             = $Algorithm
                    KeySize               = $null
                    Data                  = $EncryptedString
                    CertificateThumbprint = $Certificate.Thumbprint
                    Timestamp             = $null
                }
                $result = $script:CryptoProvider.DecryptBytes($encryptedDataObj, $Algorithm, $Certificate)
            }
            else {
                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificatePath)
                $encryptedDataObj = [PSCustomObject]@{
                    Algorithm             = $Algorithm
                    KeySize               = $null
                    Data                  = $EncryptedString
                    CertificateThumbprint = $cert.Thumbprint
                    Timestamp             = $null
                }
                $result = $script:CryptoProvider.DecryptBytes($encryptedDataObj, $Algorithm, $cert)
            }
        }
        
        return $result
    }
    catch {
        Write-Error "Failed to decrypt byte array: $($_.Exception.Message)"
        return $null
    }
}

<#
.SYNOPSIS
    Generates a new cryptographic key for the specified algorithm.
    
.DESCRIPTION
    New-CryptographyKey generates a new random key suitable for use with the specified algorithm.
    
.PARAMETER Algorithm
    The algorithm for which to generate a key.
    
.PARAMETER KeySize
    The size of the key to generate (optional).
    
.PARAMETER AsBase64
    Return the key as a Base64 encoded string instead of a byte array.
    
.EXAMPLE
    $key = New-CryptographyKey -Algorithm AES -KeySize 256
    
.EXAMPLE
    $keyString = New-CryptographyKey -Algorithm AES -AsBase64
#>
function New-CryptographyKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('AES', 'DES', 'TripleDES')]
        [string]$Algorithm,
        
        [Parameter()]
        [int]$KeySize,
        
        [Parameter()]
        [switch]$AsBase64
    )
    
    try {
        $key = $script:CryptoProvider.GenerateKey($Algorithm, $KeySize)
        
        if ($AsBase64) {
            return [System.Convert]::ToBase64String($key)
        }
        else {
            return $key
        }
    }
    catch {
        Write-Error "Failed to generate key: $($_.Exception.Message)"
        return $null
    }
}

<#
.SYNOPSIS
    Gets a list of supported cryptographic algorithms and their properties.
    
.DESCRIPTION
    Get-SupportedAlgorithms returns information about the cryptographic algorithms
    supported by the PSCryptor module.
    
.EXAMPLE
    Get-SupportedAlgorithms
    
.EXAMPLE
    $algorithms = Get-SupportedAlgorithms
    $algorithms | Where-Object { $_.Type -eq "Symmetric" }
#>
function Get-SupportedAlgorithms {
    [CmdletBinding()]
    param()
    
    try {
        return $script:CryptoProvider.GetSupportedAlgorithms()
    }
    catch {
        Write-Error "Failed to get supported algorithms: $($_.Exception.Message)"
        return $null
    }
}

<#
.SYNOPSIS
    Tests the cryptography provider functionality.
    
.DESCRIPTION
    Test-CryptographyProvider performs basic tests to ensure the cryptography
    provider is working correctly with various algorithms.
    
.PARAMETER Algorithm
    Specific algorithm to test (optional - tests all if not specified).
    
.PARAMETER Detailed
    Returns detailed test results instead of just pass/fail.
    
.EXAMPLE
    Test-CryptographyProvider
    
.EXAMPLE
    Test-CryptographyProvider -Algorithm AES -Detailed
#>
function Test-CryptographyProvider {
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('AES', 'DES', 'TripleDES', 'RSA')]
        [string]$Algorithm,
        
        [Parameter()]
        [switch]$Detailed
    )
    
    try {
        return $script:CryptoProvider.RunTests($Algorithm, $Detailed.IsPresent)
    }
    catch {
        Write-Error "Failed to run tests: $($_.Exception.Message)"
        return $null
    }
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Protect-String',
    'Unprotect-String',
    'Protect-ByteArray', 
    'Unprotect-ByteArray',
    'New-CryptographyKey',
    'Get-SupportedAlgorithms',
    'Test-CryptographyProvider'
)
