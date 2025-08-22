# PSCryptor Examples - Basic String Encryption

# Import the PSCryptor module
Import-Module (Join-Path $PSScriptRoot "..\PSCryptor.psd1") -Force

Write-Host "=== PSCryptor Basic String Encryption Examples ===" -ForegroundColor Green

# Example 1: AES Encryption
Write-Host "`n1. AES String Encryption:" -ForegroundColor Yellow
$plainText = "This is a secret message that needs to be encrypted!"
$password = "MyVerySecurePassword123!"

Write-Host "Original text: $plainText"

# Encrypt the string
$encrypted = Protect-String -PlainText $plainText -Algorithm AES -Password $password
Write-Host "Encrypted successfully with AES-$($encrypted.KeySize)"
Write-Host "Encrypted data size: $($encrypted.Data.Length) characters (Base64)"

# Decrypt the string
$decrypted = Unprotect-String -EncryptedData $encrypted -Algorithm AES -Password $password
Write-Host "Decrypted text: $decrypted"
Write-Host "Encryption/Decryption successful: $(($plainText -eq $decrypted) ? 'YES' : 'NO')" -ForegroundColor $(($plainText -eq $decrypted) ? 'Green' : 'Red')

# Example 2: Different Key Sizes
Write-Host "`n2. AES with Different Key Sizes:" -ForegroundColor Yellow
$testMessage = "Testing different key sizes"
$testPassword = "TestPassword123"

foreach ($keySize in @(128, 192, 256)) {
    $encrypted = Protect-String -PlainText $testMessage -Algorithm AES -Password $testPassword -KeySize $keySize
    $decrypted = Unprotect-String -EncryptedData $encrypted -Algorithm AES -Password $testPassword
    
    Write-Host "AES-$keySize`: " -NoNewline
    Write-Host "$(($testMessage -eq $decrypted) ? 'PASS' : 'FAIL')" -ForegroundColor $(($testMessage -eq $decrypted) ? 'Green' : 'Red')
}

# Example 3: TripleDES Encryption
Write-Host "`n3. TripleDES String Encryption:" -ForegroundColor Yellow
$encrypted3DES = Protect-String -PlainText $plainText -Algorithm TripleDES -Password $password
$decrypted3DES = Unprotect-String -EncryptedData $encrypted3DES -Algorithm TripleDES -Password $password

Write-Host "TripleDES encryption: $(($plainText -eq $decrypted3DES) ? 'PASS' : 'FAIL')" -ForegroundColor $(($plainText -eq $decrypted3DES) ? 'Green' : 'Red')

# Example 4: Pipeline Support
Write-Host "`n4. Pipeline Support:" -ForegroundColor Yellow
$messages = @("Message 1", "Message 2", "Message 3")
$encryptedMessages = $messages | ForEach-Object { 
    Protect-String -PlainText $_ -Algorithm AES -Password $password 
}

$decryptedMessages = $encryptedMessages | ForEach-Object { 
    Unprotect-String -EncryptedData $_ -Algorithm AES -Password $password 
}

Write-Host "Pipeline encryption of multiple messages:"
for ($i = 0; $i -lt $messages.Count; $i++) {
    $match = $messages[$i] -eq $decryptedMessages[$i]
    Write-Host "  Message $($i+1): $(($match) ? 'PASS' : 'FAIL')" -ForegroundColor $(($match) ? 'Green' : 'Red')
}

# Example 5: Custom Salt
Write-Host "`n5. Custom Salt Usage:" -ForegroundColor Yellow
$customSalt = [System.Text.Encoding]::UTF8.GetBytes("MyCustomSalt123")
$encryptedWithSalt = Protect-String -PlainText $plainText -Algorithm AES -Password $password -Salt $customSalt
$decryptedWithSalt = Unprotect-String -EncryptedData $encryptedWithSalt -Algorithm AES -Password $password

Write-Host "Custom salt encryption: $(($plainText -eq $decryptedWithSalt) ? 'PASS' : 'FAIL')" -ForegroundColor $(($plainText -eq $decryptedWithSalt) ? 'Green' : 'Red')

Write-Host "`n=== Basic String Encryption Examples Complete ===" -ForegroundColor Green
