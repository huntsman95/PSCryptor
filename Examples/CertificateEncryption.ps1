# PSCryptor Examples - Certificate-based Encryption

# Import the PSCryptor module
Import-Module (Join-Path $PSScriptRoot "..\PSCryptor.psd1") -Force

Write-Host "=== PSCryptor Certificate-based Encryption Examples ===" -ForegroundColor Green

# Example 1: Create a self-signed certificate for testing
Write-Host "`n1. Creating Self-Signed Certificate for Testing:" -ForegroundColor Yellow

try {
    # Create a self-signed certificate (requires elevated permissions on some systems)
    $cert = New-SelfSignedCertificate -Subject "CN=PSCryptorTest" -KeyUsage DigitalSignature,KeyEncipherment -Type DocumentEncryptionCert -CertStoreLocation Cert:\CurrentUser\My
    Write-Host "Created test certificate: $($cert.Subject)" -ForegroundColor Green
    Write-Host "Certificate thumbprint: $($cert.Thumbprint)"
    Write-Host "Has private key: $($cert.HasPrivateKey)"
    
    # Example 2: RSA Encryption with Certificate
    Write-Host "`n2. RSA Encryption with Certificate:" -ForegroundColor Yellow
    $plainText = "This is a secret message encrypted with RSA!"
    
    Write-Host "Original text: $plainText"
    
    # Encrypt with certificate
    $encrypted = Protect-String -PlainText $plainText -Algorithm RSA -Certificate $cert
    Write-Host "Encrypted successfully with RSA-$($encrypted.KeySize)"
    Write-Host "Certificate thumbprint in encrypted data: $($encrypted.CertificateThumbprint)"
    
    # Decrypt with certificate
    $decrypted = Unprotect-String -EncryptedData $encrypted -Algorithm RSA -Certificate $cert
    Write-Host "Decrypted text: $decrypted"
    Write-Host "RSA Encryption/Decryption successful: $(($plainText -eq $decrypted) ? 'YES' : 'NO')" -ForegroundColor $(($plainText -eq $decrypted) ? 'Green' : 'Red')
    
    # Example 3: Byte Array Encryption with Certificate
    Write-Host "`n3. Byte Array Encryption with Certificate:" -ForegroundColor Yellow
    $data = [System.Text.Encoding]::UTF8.GetBytes("Binary data to encrypt")
    
    $encryptedBytes = Protect-ByteArray -Data $data -Algorithm RSA -Certificate $cert
    $decryptedBytes = Unprotect-ByteArray -EncryptedData $encryptedBytes -Algorithm RSA -Certificate $cert
    $decryptedString = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
    
    $originalString = [System.Text.Encoding]::UTF8.GetString($data)
    Write-Host "Original: $originalString"
    Write-Host "Decrypted: $decryptedString"
    Write-Host "Byte array encryption: $(($originalString -eq $decryptedString) ? 'PASS' : 'FAIL')" -ForegroundColor $(($originalString -eq $decryptedString) ? 'Green' : 'Red')
    
    # Example 4: Certificate from File Path
    Write-Host "`n4. Exporting and Using Certificate from File:" -ForegroundColor Yellow
    
    # Export certificate to temporary file
    $tempCertPath = Join-Path $env:TEMP "PSCryptorTest.cer"
    $certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    [System.IO.File]::WriteAllBytes($tempCertPath, $certBytes)
    
    # Note: This will only work for public key operations since we're exporting without private key
    Write-Host "Certificate exported to: $tempCertPath"
    Write-Host "Note: File-based certificate operations require certificates with private keys to be properly installed."
    
    # Clean up temporary file
    if (Test-Path $tempCertPath) {
        Remove-Item $tempCertPath -Force
    }
    
    # Clean up test certificate
    Write-Host "`n5. Cleaning up test certificate..." -ForegroundColor Yellow
    Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -Force
    Write-Host "Test certificate removed from certificate store."
    
}
catch {
    Write-Host "Error in certificate operations: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "This might be due to insufficient permissions or system configuration." -ForegroundColor Yellow
    Write-Host "Try running PowerShell as Administrator or check certificate store permissions." -ForegroundColor Yellow
}

# Example 6: Finding Existing Certificates
Write-Host "`n6. Finding Existing Certificates:" -ForegroundColor Yellow

$certs = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.HasPrivateKey }
if ($certs.Count -gt 0) {
    Write-Host "Found $($certs.Count) certificate(s) with private keys in CurrentUser\My store:"
    foreach ($certificate in $certs) {
        Write-Host "  Subject: $($certificate.Subject)"
        Write-Host "  Thumbprint: $($certificate.Thumbprint)"
        Write-Host "  Key Size: $($certificate.PublicKey.Key.KeySize) bits"
        Write-Host "  Valid: $($certificate.NotBefore) to $($certificate.NotAfter)"
        Write-Host ""
    }
    
    # Test with first available certificate
    $testCert = $certs[0]
    Write-Host "Testing with certificate: $($testCert.Subject)" -ForegroundColor Cyan
    
    try {
        $testMessage = "Testing with existing certificate"
        $encrypted = Protect-String -PlainText $testMessage -Algorithm RSA -Certificate $testCert
        $decrypted = Unprotect-String -EncryptedData $encrypted -Algorithm RSA -Certificate $testCert
        
        Write-Host "Existing certificate test: $(($testMessage -eq $decrypted) ? 'PASS' : 'FAIL')" -ForegroundColor $(($testMessage -eq $decrypted) ? 'Green' : 'Red')
    }
    catch {
        Write-Host "Error testing with existing certificate: $($_.Exception.Message)" -ForegroundColor Red
    }
}
else {
    Write-Host "No certificates with private keys found in CurrentUser\My store."
    Write-Host "You can create one using: New-SelfSignedCertificate -Subject 'CN=YourName' -KeyUsage DigitalSignature,KeyEncipherment -Type DocumentEncryptionCert -CertStoreLocation Cert:\CurrentUser\My"
}

Write-Host "`n=== Certificate-based Encryption Examples Complete ===" -ForegroundColor Green
