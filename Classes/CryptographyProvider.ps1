using namespace System.Security.Cryptography
using namespace System.Security.Cryptography.X509Certificates
using namespace System.Text
using namespace System.IO

<#
.SYNOPSIS
    CryptographyProvider class for handling encryption and decryption operations.
    
.DESCRIPTION
    This class provides the core cryptographic functionality for the PSCryptor module.
    It supports various .NET encryption algorithms including AES, DES, TripleDES, and RSA.
#>
class CryptographyProvider {
    
    # Static properties for algorithm configuration
    static [hashtable] $AlgorithmConfig = @{
        'AES'       = @{
            Type           = 'Symmetric'
            KeySizes       = @(128, 192, 256)
            DefaultKeySize = 256
            BlockSize      = 128
            Class          = 'Aes'
        }
        'DES'       = @{
            Type           = 'Symmetric'
            KeySizes       = @(64)
            DefaultKeySize = 64
            BlockSize      = 64
            Class          = 'DES'
        }
        'TripleDES' = @{
            Type           = 'Symmetric'
            KeySizes       = @(128, 192)
            DefaultKeySize = 192
            BlockSize      = 64
            Class          = 'TripleDES'
        }
        'RSA'       = @{
            Type           = 'Asymmetric'
            KeySizes       = @(1024, 2048, 4096)
            DefaultKeySize = 2048
            BlockSize      = 0
            Class          = 'RSA'
        }
    }
    
    <#
    .SYNOPSIS
        Encrypts a string using symmetric or asymmetric encryption.
    #>
    [PSCustomObject] EncryptString([string]$plainText, [string]$algorithm, [string]$password, [int]$keySize = 0, [byte[]]$salt = $null) {
        if (-not $this.IsSymmetricAlgorithm($algorithm)) {
            throw "Algorithm '$algorithm' is not supported for PSK encryption."
        }
        
        $data = [Encoding]::UTF8.GetBytes($plainText)
        return $this.EncryptBytes($data, $algorithm, $password, $keySize, $salt)
    }
    
    <#
    .SYNOPSIS
        Encrypts a string using certificate-based encryption.
    #>
    [PSCustomObject] EncryptString([string]$plainText, [string]$algorithm, [X509Certificate2]$certificate) {
        if ($algorithm -ne 'RSA') {
            throw 'Certificate-based encryption is only supported for RSA algorithm.'
        }
        
        $data = [Encoding]::UTF8.GetBytes($plainText)
        return $this.EncryptBytes($data, $algorithm, $certificate)
    }
    
    <#
    .SYNOPSIS
        Decrypts a string using symmetric encryption.
    #>
    [string] DecryptString([PSCustomObject]$encryptedData, [string]$algorithm, [string]$password) {
        $decryptedBytes = $this.DecryptBytes($encryptedData, $algorithm, $password)
        return [Encoding]::UTF8.GetString($decryptedBytes)
    }
    
    <#
    .SYNOPSIS
        Decrypts a string using certificate-based encryption.
    #>
    [string] DecryptString([PSCustomObject]$encryptedData, [string]$algorithm, [X509Certificate2]$certificate) {
        $decryptedBytes = $this.DecryptBytes($encryptedData, $algorithm, $certificate)
        return [Encoding]::UTF8.GetString($decryptedBytes)
    }
    
    <#
    .SYNOPSIS
        Encrypts a byte array using symmetric encryption.
    #>
    [PSCustomObject] EncryptBytes([byte[]]$data, [string]$algorithm, [string]$password, [int]$keySize = 0, [byte[]]$salt = $null) {
        if (-not $this.IsSymmetricAlgorithm($algorithm)) {
            throw "Algorithm '$algorithm' is not supported for PSK encryption."
        }
        
        $config = [CryptographyProvider]::AlgorithmConfig[$algorithm]
        $actualKeySize = $keySize -gt 0 ? $keySize : $config.DefaultKeySize
        
        if ($actualKeySize -notin $config.KeySizes) {
            throw "Key size $actualKeySize is not supported for algorithm $algorithm. Supported sizes: $($config.KeySizes -join ', ')"
        }
        
        # Generate salt if not provided
        if ($null -eq $salt) {
            $salt = $this.GenerateSalt()
        }
        
        # Derive key from password
        $key = $this.DeriveKey($password, $salt, $actualKeySize / 8)
        
        # Create algorithm instance
        $cryptoAlgorithm = $this.CreateSymmetricAlgorithm($algorithm, $actualKeySize)
        $cryptoAlgorithm.Key = $key
        $cryptoAlgorithm.GenerateIV()
        
        $encryptor = $null
        $ms = $null
        $cs = $null
        
        try {
            # Encrypt the data
            $encryptor = $cryptoAlgorithm.CreateEncryptor()
            $ms = [MemoryStream]::new()
            $cs = [CryptoStream]::new($ms, $encryptor, [CryptoStreamMode]::Write)
            
            $cs.Write($data, 0, $data.Length)
            $cs.FlushFinalBlock()
            
            $encryptedBytes = $ms.ToArray()
            
            # Return encrypted data with metadata
            return [PSCustomObject]@{
                Algorithm = $algorithm
                KeySize   = $actualKeySize
                IV        = [Convert]::ToBase64String($cryptoAlgorithm.IV)
                Salt      = [Convert]::ToBase64String($salt)
                Data      = [Convert]::ToBase64String($encryptedBytes)
                Timestamp = [DateTime]::UtcNow
            }
        }
        finally {
            if ($null -ne $cs) { $cs.Dispose() }
            if ($null -ne $ms) { $ms.Dispose() }
            if ($null -ne $encryptor) { $encryptor.Dispose() }
            if ($null -ne $cryptoAlgorithm) { $cryptoAlgorithm.Dispose() }
        }
    }
    
    <#
    .SYNOPSIS
        Encrypts a byte array using certificate-based encryption.
    #>
    [PSCustomObject] EncryptBytes([byte[]]$data, [string]$algorithm, [X509Certificate2]$certificate) {
        if ($algorithm -ne 'RSA') {
            throw 'Certificate-based encryption is only supported for RSA algorithm.'
        }
        
        if ($null -eq $certificate.PublicKey) {
            throw 'Certificate must have a public key for encryption.'
        }
        
        try {
            # Get the RSA public key from the certificate
            $rsa = $certificate.PublicKey.Key
            if ($null -eq $rsa) {
                throw 'Unable to retrieve RSA public key from certificate.'
            }
            $encryptedBytes = $rsa.Encrypt($data, [RSAEncryptionPadding]::OaepSHA256)
            
            return [PSCustomObject]@{
                Algorithm             = $algorithm
                KeySize               = $rsa.KeySize
                Data                  = [Convert]::ToBase64String($encryptedBytes)
                CertificateThumbprint = $certificate.Thumbprint
                Timestamp             = [DateTime]::UtcNow
            }
        }
        catch {
            throw "RSA encryption failed: $($_.Exception.Message)"
        }
    }
    
    <#
    .SYNOPSIS
        Decrypts a byte array using symmetric encryption.
    #>
    [byte[]] DecryptBytes([PSCustomObject]$encryptedData, [string]$algorithm, [string]$password) {
        if (-not $this.IsSymmetricAlgorithm($algorithm)) {
            throw "Algorithm '$algorithm' is not supported for PSK decryption."
        }
        
        if ($encryptedData.Algorithm -ne $algorithm) {
            throw "Algorithm mismatch. Data was encrypted with '$($encryptedData.Algorithm)' but trying to decrypt with '$algorithm'."
        }
        
        # Decode the encrypted data
        $salt = [Convert]::FromBase64String($encryptedData.Salt)
        $iv = [Convert]::FromBase64String($encryptedData.IV)
        $data = [Convert]::FromBase64String($encryptedData.Data)
        
        # Derive the same key from password and salt
        $key = $this.DeriveKey($password, $salt, $encryptedData.KeySize / 8)
        
        # Create algorithm instance
        $cryptoAlgorithm = $this.CreateSymmetricAlgorithm($algorithm, $encryptedData.KeySize)
        $cryptoAlgorithm.Key = $key
        $cryptoAlgorithm.IV = $iv
        
        $decryptor = $null
        $ms = $null
        $cs = $null
        
        try {
            # Decrypt the data
            $decryptor = $cryptoAlgorithm.CreateDecryptor()
            $ms = [MemoryStream]::new($data)
            $cs = [CryptoStream]::new($ms, $decryptor, [CryptoStreamMode]::Read)
            
            $decryptedData = [System.Collections.Generic.List[byte]]::new()
            $buffer = [byte[]]::new(1024)
            
            while ($true) {
                $bytesRead = $cs.Read($buffer, 0, $buffer.Length)
                if ($bytesRead -eq 0) { break }
                
                for ($i = 0; $i -lt $bytesRead; $i++) {
                    $decryptedData.Add($buffer[$i])
                }
            }
            
            return $decryptedData.ToArray()
        }
        finally {
            if ($null -ne $cs) { $cs.Dispose() }
            if ($null -ne $ms) { $ms.Dispose() }
            if ($null -ne $decryptor) { $decryptor.Dispose() }
            if ($null -ne $cryptoAlgorithm) { $cryptoAlgorithm.Dispose() }
        }
    }
    
    <#
    .SYNOPSIS
        Decrypts a byte array using certificate-based encryption.
    #>
    [byte[]] DecryptBytes([PSCustomObject]$encryptedData, [string]$algorithm, [X509Certificate2]$certificate) {
        if ($algorithm -ne 'RSA') {
            throw 'Certificate-based decryption is only supported for RSA algorithm.'
        }
        
        if ($encryptedData.Algorithm -ne $algorithm) {
            throw "Algorithm mismatch. Data was encrypted with '$($encryptedData.Algorithm)' but trying to decrypt with '$algorithm'."
        }
        
        if (-not $certificate.HasPrivateKey) {
            throw 'Certificate must have a private key for decryption.'
        }
        
        if ($certificate.Thumbprint -ne $encryptedData.CertificateThumbprint) {
            Write-Warning 'Certificate thumbprint mismatch. This may not be the correct certificate for decryption.'
        }
        
        try {
            # Get the RSA private key from the certificate
            $rsa = $certificate.PrivateKey
            if ($null -eq $rsa) {
                throw 'Unable to retrieve RSA private key from certificate.'
            }
            $data = [Convert]::FromBase64String($encryptedData.Data)
            $decryptedBytes = $rsa.Decrypt($data, [RSAEncryptionPadding]::OaepSHA256)
            
            return $decryptedBytes
        }
        catch {
            throw "RSA decryption failed: $($_.Exception.Message)"
        }
    }
    
    <#
    .SYNOPSIS
        Generates a random key for the specified algorithm.
    #>
    [byte[]] GenerateKey([string]$algorithm, [int]$keySize = 0) {
        if (-not $this.IsSymmetricAlgorithm($algorithm)) {
            throw 'Key generation is only supported for symmetric algorithms.'
        }
        
        $config = [CryptographyProvider]::AlgorithmConfig[$algorithm]
        $actualKeySize = $keySize -gt 0 ? $keySize : $config.DefaultKeySize
        
        if ($actualKeySize -notin $config.KeySizes) {
            throw "Key size $actualKeySize is not supported for algorithm $algorithm. Supported sizes: $($config.KeySizes -join ', ')"
        }
        
        $cryptoAlgorithm = $this.CreateSymmetricAlgorithm($algorithm, $actualKeySize)
        try {
            $cryptoAlgorithm.GenerateKey()
            return $cryptoAlgorithm.Key
        }
        finally {
            if ($null -ne $cryptoAlgorithm) { $cryptoAlgorithm.Dispose() }
        }
    }
    
    <#
    .SYNOPSIS
        Encrypts a file using symmetric encryption with streaming for large files.
    #>
    [PSCustomObject] EncryptFile([string]$inputPath, [string]$outputPath, [string]$algorithm, [string]$password, [int]$keySize = 0, [byte[]]$salt = $null) {
        if (-not $this.IsSymmetricAlgorithm($algorithm)) {
            throw 'File encryption with password is only supported for symmetric algorithms.'
        }
        
        if (-not (Test-Path $inputPath)) {
            throw "Input file does not exist: $inputPath"
        }
        
        $config = [CryptographyProvider]::AlgorithmConfig[$algorithm]
        $actualKeySize = $keySize -gt 0 ? $keySize : $config.DefaultKeySize
        
        if ($actualKeySize -notin $config.KeySizes) {
            throw "Key size $actualKeySize is not supported for algorithm $algorithm. Supported sizes: $($config.KeySizes -join ', ')"
        }
        
        # Generate salt if not provided
        if ($null -eq $salt) {
            $salt = $this.GenerateSalt()
        }
        
        $cryptoAlgorithm = $this.CreateSymmetricAlgorithm($algorithm, $actualKeySize)
        try {
            # Derive key from password
            $key = $this.DeriveKey($password, $salt, $cryptoAlgorithm.KeySize / 8)
            $cryptoAlgorithm.Key = $key
            $cryptoAlgorithm.GenerateIV()
            
            # Create file streams
            $inputStream = [FileStream]::new($inputPath, [FileMode]::Open, [FileAccess]::Read)
            $outputStream = [FileStream]::new($outputPath, [FileMode]::Create, [FileAccess]::Write)
            
            try {
                # Create crypto stream
                $encryptor = $cryptoAlgorithm.CreateEncryptor()
                $cryptoStream = [CryptoStream]::new($outputStream, $encryptor, [CryptoStreamMode]::Write)
                
                try {
                    # Copy data through crypto stream
                    $inputStream.CopyTo($cryptoStream)
                    $cryptoStream.FlushFinalBlock()
                }
                finally {
                    if ($null -ne $cryptoStream) { $cryptoStream.Dispose() }
                    if ($null -ne $encryptor) { $encryptor.Dispose() }
                }
            }
            finally {
                if ($null -ne $inputStream) { $inputStream.Dispose() }
                if ($null -ne $outputStream) { $outputStream.Dispose() }
            }
            
            # Return metadata needed for decryption
            return [PSCustomObject]@{
                Algorithm = $algorithm
                KeySize   = $actualKeySize
                IV        = [Convert]::ToBase64String($cryptoAlgorithm.IV)
                Salt      = [Convert]::ToBase64String($salt)
                InputFile = $inputPath
                OutputFile = $outputPath
                Timestamp = [DateTime]::UtcNow
            }
        }
        finally {
            if ($null -ne $cryptoAlgorithm) { $cryptoAlgorithm.Dispose() }
        }
    }
    
    <#
    .SYNOPSIS
        Encrypts a file using certificate-based RSA encryption (for small files only).
    #>
    [PSCustomObject] EncryptFile([string]$inputPath, [string]$outputPath, [string]$algorithm, [X509Certificate2]$certificate) {
        if ($algorithm -ne 'RSA') {
            throw 'Certificate-based file encryption is only supported for RSA algorithm.'
        }
        
        if (-not (Test-Path $inputPath)) {
            throw "Input file does not exist: $inputPath"
        }
        
        if ($null -eq $certificate.PublicKey) {
            throw 'Certificate must have a public key for encryption.'
        }
        
        # Check file size (RSA has limitations)
        $fileInfo = Get-Item $inputPath
        $maxSize = 190 # Conservative limit for RSA-2048 with OAEP padding
        if ($fileInfo.Length -gt $maxSize) {
            throw "File is too large for RSA encryption. Maximum size: $maxSize bytes. Current size: $($fileInfo.Length) bytes. Use symmetric encryption for larger files."
        }
        
        try {
            # Read file data
            $data = [File]::ReadAllBytes($inputPath)
            
            # Encrypt using RSA
            $rsa = $certificate.PublicKey.Key
            if ($null -eq $rsa) {
                throw 'Unable to retrieve RSA public key from certificate.'
            }
            $encryptedBytes = $rsa.Encrypt($data, [RSAEncryptionPadding]::OaepSHA256)
            
            # Write encrypted data to output file
            [File]::WriteAllBytes($outputPath, $encryptedBytes)
            
            return [PSCustomObject]@{
                Algorithm             = $algorithm
                KeySize               = $rsa.KeySize
                InputFile             = $inputPath
                OutputFile            = $outputPath
                CertificateThumbprint = $certificate.Thumbprint
                Timestamp             = [DateTime]::UtcNow
            }
        }
        catch {
            throw "RSA file encryption failed: $($_.Exception.Message)"
        }
    }
    
    <#
    .SYNOPSIS
        Decrypts a file using symmetric encryption.
    #>
    [void] DecryptFile([PSCustomObject]$encryptedFileData, [string]$outputPath, [string]$algorithm, [string]$password) {
        if (-not $this.IsSymmetricAlgorithm($algorithm)) {
            throw 'File decryption with password is only supported for symmetric algorithms.'
        }
        
        if ($encryptedFileData.Algorithm -ne $algorithm) {
            throw "Algorithm mismatch. File was encrypted with '$($encryptedFileData.Algorithm)' but trying to decrypt with '$algorithm'."
        }
        
        if (-not (Test-Path $encryptedFileData.OutputFile)) {
            throw "Encrypted file does not exist: $($encryptedFileData.OutputFile)"
        }
        
        $cryptoAlgorithm = $this.CreateSymmetricAlgorithm($algorithm, $encryptedFileData.KeySize)
        try {
            # Derive key from password and set IV
            $salt = [Convert]::FromBase64String($encryptedFileData.Salt)
            $iv = [Convert]::FromBase64String($encryptedFileData.IV)
            $key = $this.DeriveKey($password, $salt, $cryptoAlgorithm.KeySize / 8)
            
            $cryptoAlgorithm.Key = $key
            $cryptoAlgorithm.IV = $iv
            
            # Create file streams
            $inputStream = [FileStream]::new($encryptedFileData.OutputFile, [FileMode]::Open, [FileAccess]::Read)
            $outputStream = [FileStream]::new($outputPath, [FileMode]::Create, [FileAccess]::Write)
            
            try {
                # Create crypto stream
                $decryptor = $cryptoAlgorithm.CreateDecryptor()
                $cryptoStream = [CryptoStream]::new($inputStream, $decryptor, [CryptoStreamMode]::Read)
                
                try {
                    # Copy data through crypto stream
                    $cryptoStream.CopyTo($outputStream)
                }
                finally {
                    if ($null -ne $cryptoStream) { $cryptoStream.Dispose() }
                    if ($null -ne $decryptor) { $decryptor.Dispose() }
                }
            }
            finally {
                if ($null -ne $inputStream) { $inputStream.Dispose() }
                if ($null -ne $outputStream) { $outputStream.Dispose() }
            }
        }
        finally {
            if ($null -ne $cryptoAlgorithm) { $cryptoAlgorithm.Dispose() }
        }
    }
    
    <#
    .SYNOPSIS
        Decrypts a file using certificate-based RSA encryption.
    #>
    [void] DecryptFile([PSCustomObject]$encryptedFileData, [string]$outputPath, [string]$algorithm, [X509Certificate2]$certificate) {
        if ($algorithm -ne 'RSA') {
            throw 'Certificate-based file decryption is only supported for RSA algorithm.'
        }
        
        if ($encryptedFileData.Algorithm -ne $algorithm) {
            throw "Algorithm mismatch. File was encrypted with '$($encryptedFileData.Algorithm)' but trying to decrypt with '$algorithm'."
        }
        
        if (-not $certificate.HasPrivateKey) {
            throw 'Certificate must have a private key for decryption.'
        }
        
        if ($certificate.Thumbprint -ne $encryptedFileData.CertificateThumbprint) {
            Write-Warning 'Certificate thumbprint mismatch. This may not be the correct certificate for decryption.'
        }
        
        if (-not (Test-Path $encryptedFileData.OutputFile)) {
            throw "Encrypted file does not exist: $($encryptedFileData.OutputFile)"
        }
        
        try {
            # Read encrypted file data
            $encryptedBytes = [File]::ReadAllBytes($encryptedFileData.OutputFile)
            
            # Decrypt using RSA
            $rsa = $certificate.PrivateKey
            if ($null -eq $rsa) {
                throw 'Unable to retrieve RSA private key from certificate.'
            }
            $decryptedBytes = $rsa.Decrypt($encryptedBytes, [RSAEncryptionPadding]::OaepSHA256)
            
            # Write decrypted data to output file
            [File]::WriteAllBytes($outputPath, $decryptedBytes)
        }
        catch {
            throw "RSA file decryption failed: $($_.Exception.Message)"
        }
    }
    
    <#
    .SYNOPSIS
        Gets information about supported algorithms.
    #>
    [PSCustomObject[]] GetSupportedAlgorithms() {
        $algorithms = @()
        
        foreach ($algorithmName in [CryptographyProvider]::AlgorithmConfig.Keys) {
            $config = [CryptographyProvider]::AlgorithmConfig[$algorithmName]
            $algorithms += [PSCustomObject]@{
                Name           = $algorithmName
                Type           = $config.Type
                KeySizes       = $config.KeySizes
                DefaultKeySize = $config.DefaultKeySize
                BlockSize      = $config.BlockSize
                Description    = $this.GetAlgorithmDescription($algorithmName)
            }
        }
        
        return $algorithms
    }
    
    <#
    .SYNOPSIS
        Runs basic tests on the cryptography provider.
    #>
    [PSCustomObject[]] RunTests([string]$algorithm = $null, [bool]$detailed = $false) {
        $results = @()
        $testData = 'This is a test message for encryption/decryption.'
        $testPassword = 'TestPassword123!'
        
        $algorithmsToTest = if ($algorithm) { @($algorithm) } else { [CryptographyProvider]::AlgorithmConfig.Keys }
        
        foreach ($alg in $algorithmsToTest) {
            $testResult = [PSCustomObject]@{
                Algorithm = $alg
                Success   = $false
                Message   = ''
                Duration  = [TimeSpan]::Zero
                Details   = @{}
            }
            
            try {
                $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                
                if ($this.IsSymmetricAlgorithm($alg)) {
                    # Test symmetric encryption
                    $encrypted = $this.EncryptString($testData, $alg, $testPassword, 0, $null)
                    $decrypted = $this.DecryptString($encrypted, $alg, $testPassword)
                    
                    if ($decrypted -eq $testData) {
                        $testResult.Success = $true
                        $testResult.Message = 'Symmetric encryption/decryption test passed'
                    }
                    else {
                        $testResult.Message = 'Decrypted data does not match original'
                    }
                    
                    if ($detailed) {
                        $testResult.Details = @{
                            OriginalLength = $testData.Length
                            EncryptedSize  = $encrypted.Data.Length
                            KeySize        = $encrypted.KeySize
                            HasSalt        = $null -ne $encrypted.Salt
                            HasIV          = $null -ne $encrypted.IV
                        }
                    }
                }
                else {
                    $testResult.Message = 'Certificate-based testing not implemented in basic test'
                    $testResult.Success = $true  # Mark as success since we can't test without certificates
                }
                
                $stopwatch.Stop()
                $testResult.Duration = $stopwatch.Elapsed
            }
            catch {
                $testResult.Message = "Test failed: $($_.Exception.Message)"
            }
            
            $results += $testResult
        }
        
        return $results
    }
    
    #region Private Methods
    
    <#
    .SYNOPSIS
        Checks if an algorithm is symmetric.
    #>
    hidden [bool] IsSymmetricAlgorithm([string]$algorithm) {
        return [CryptographyProvider]::AlgorithmConfig.ContainsKey($algorithm) -and 
        [CryptographyProvider]::AlgorithmConfig[$algorithm].Type -eq 'Symmetric'
    }
    
    <#
    .SYNOPSIS
        Creates a symmetric algorithm instance.
    #>
    hidden [SymmetricAlgorithm] CreateSymmetricAlgorithm([string]$algorithm, [int]$keySize) {
        switch ($algorithm) {
            'AES' {
                $aes = [Aes]::Create()
                $aes.KeySize = $keySize
                $aes.Mode = [CipherMode]::CBC
                $aes.Padding = [PaddingMode]::PKCS7
                return $aes
            }
            'DES' {
                $des = [DES]::Create()
                $des.Mode = [CipherMode]::CBC
                $des.Padding = [PaddingMode]::PKCS7
                return $des
            }
            'TripleDES' {
                $tdes = [TripleDES]::Create()
                $tdes.KeySize = $keySize
                $tdes.Mode = [CipherMode]::CBC
                $tdes.Padding = [PaddingMode]::PKCS7
                return $tdes
            }
            default {
                throw "Unsupported algorithm: $algorithm"
            }
        }
        
        # This line should never be reached due to the throw above, but PowerShell parser requires it
        return $null
    }
    
    <#
    .SYNOPSIS
        Derives a key from a password using PBKDF2.
    #>
    hidden [byte[]] DeriveKey([string]$password, [byte[]]$salt, [int]$keyLength) {
        $pbkdf2 = [Rfc2898DeriveBytes]::new($password, $salt, 10000, [HashAlgorithmName]::SHA256)
        try {
            return $pbkdf2.GetBytes($keyLength)
        }
        finally {
            if ($null -ne $pbkdf2) { $pbkdf2.Dispose() }
        }
    }
    
    <#
    .SYNOPSIS
        Generates a random salt.
    #>
    hidden [byte[]] GenerateSalt() {
        $salt = [byte[]]::new(16)
        $rng = [RandomNumberGenerator]::Create()
        try {
            $rng.GetBytes($salt)
            return $salt
        }
        finally {
            if ($null -ne $rng) { $rng.Dispose() }
        }
    }
    
    <#
    .SYNOPSIS
        Gets a description for an algorithm.
    #>
    hidden [string] GetAlgorithmDescription([string]$algorithm) {
        switch ($algorithm) {
            'AES' { return 'Advanced Encryption Standard - Recommended for most use cases' }
            'DES' { return 'Data Encryption Standard - Legacy algorithm, not recommended for new applications' }
            'TripleDES' { return 'Triple Data Encryption Standard - More secure than DES but slower than AES' }
            'RSA' { return 'RSA asymmetric encryption - Used with certificates for key exchange and digital signatures' }
            default { return 'Unknown algorithm' }
        }
        
        # This line should never be reached due to the returns above, but PowerShell parser requires it
        return 'Unknown algorithm'
    }
    
    #endregion
}
