# PSCryptor Test Suite

# Import the PSCryptor module
Import-Module (Join-Path $PSScriptRoot "..\PSCryptor.psd1") -Force

Write-Host "=== PSCryptor Module Test Suite ===" -ForegroundColor Green

# Test 1: Module Import and Function Availability
Write-Host "`n1. Testing Module Import and Function Availability:" -ForegroundColor Yellow
$expectedFunctions = @(
    'Protect-String',
    'Unprotect-String',
    'Protect-ByteArray',
    'Unprotect-ByteArray',
    'New-CryptographyKey',
    'Get-SupportedAlgorithms',
    'Test-CryptographyProvider'
)

$module = Get-Module PSCryptor
if ($module) {
    Write-Host "✓ Module imported successfully" -ForegroundColor Green
    Write-Host "  Version: $($module.Version)"
    Write-Host "  Path: $($module.Path)"
    
    foreach ($func in $expectedFunctions) {
        if (Get-Command $func -ErrorAction SilentlyContinue) {
            Write-Host "  ✓ $func available" -ForegroundColor Green
        } else {
            Write-Host "  ✗ $func missing" -ForegroundColor Red
        }
    }
} else {
    Write-Host "✗ Module import failed" -ForegroundColor Red
}

# Test 2: Get Supported Algorithms
Write-Host "`n2. Testing Get-SupportedAlgorithms:" -ForegroundColor Yellow
try {
    $algorithms = Get-SupportedAlgorithms
    if ($algorithms) {
        Write-Host "✓ Get-SupportedAlgorithms successful" -ForegroundColor Green
        foreach ($alg in $algorithms) {
            Write-Host "  $($alg.Name) ($($alg.Type)): Key sizes $($alg.KeySizes -join ', ') bits"
        }
    } else {
        Write-Host "✗ Get-SupportedAlgorithms returned no data" -ForegroundColor Red
    }
} catch {
    Write-Host "✗ Get-SupportedAlgorithms failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 3: Key Generation
Write-Host "`n3. Testing Key Generation:" -ForegroundColor Yellow
$keyTests = @(
    @{ Algorithm = 'AES'; KeySize = 128 },
    @{ Algorithm = 'AES'; KeySize = 256 },
    @{ Algorithm = 'TripleDES'; KeySize = 192 }
)

foreach ($test in $keyTests) {
    try {
        $key = New-CryptographyKey -Algorithm $test.Algorithm -KeySize $test.KeySize
        $keyBase64 = New-CryptographyKey -Algorithm $test.Algorithm -KeySize $test.KeySize -AsBase64
        
        if ($key -and $keyBase64) {
            Write-Host "  ✓ $($test.Algorithm)-$($test.KeySize) key generation successful" -ForegroundColor Green
            Write-Host "    Binary key length: $($key.Length) bytes"
            Write-Host "    Base64 key length: $($keyBase64.Length) characters"
        } else {
            Write-Host "  ✗ $($test.Algorithm)-$($test.KeySize) key generation failed" -ForegroundColor Red
        }
    } catch {
        Write-Host "  ✗ $($test.Algorithm)-$($test.KeySize) key generation error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Test 4: Built-in Test Function
Write-Host "`n4. Running Built-in Module Tests:" -ForegroundColor Yellow
try {
    $testResults = Test-CryptographyProvider -Detailed
    if ($testResults) {
        Write-Host "✓ Test-CryptographyProvider completed" -ForegroundColor Green
        foreach ($result in $testResults) {
            $status = $result.Success ? "✓" : "✗"
            $color = $result.Success ? "Green" : "Red"
            Write-Host "  $status $($result.Algorithm): $($result.Message)" -ForegroundColor $color
            Write-Host "    Duration: $($result.Duration.TotalMilliseconds) ms"
            
            if ($result.Details.Count -gt 0) {
                foreach ($detail in $result.Details.GetEnumerator()) {
                    Write-Host "    $($detail.Key): $($detail.Value)"
                }
            }
        }
    } else {
        Write-Host "✗ Test-CryptographyProvider returned no results" -ForegroundColor Red
    }
} catch {
    Write-Host "✗ Test-CryptographyProvider failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 5: Comprehensive Encryption/Decryption Tests
Write-Host "`n5. Comprehensive Encryption/Decryption Tests:" -ForegroundColor Yellow

$testData = @(
    "Simple text",
    "Text with special characters: !@#$%^&*()",
    "Unicode text: 你好世界 🌍",
    "Multi-line`ntext`nwith`nline breaks",
    "Very long text: " + ("A" * 1000)
)

$algorithms = @('AES', 'TripleDES')
$password = "TestPassword123!"

foreach ($alg in $algorithms) {
    Write-Host "  Testing $alg algorithm:" -ForegroundColor Cyan
    $algorithmPassed = $true
    
    foreach ($data in $testData) {
        try {
            # Test string encryption
            $encrypted = Protect-String -PlainText $data -Algorithm $alg -Password $password
            $decrypted = Unprotect-String -EncryptedData $encrypted -Algorithm $alg -Password $password
            
            if ($data -eq $decrypted) {
                Write-Host "    ✓ String test passed (length: $($data.Length))" -ForegroundColor Green
            } else {
                Write-Host "    ✗ String test failed (length: $($data.Length))" -ForegroundColor Red
                $algorithmPassed = $false
            }
            
            # Test byte array encryption
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($data)
            $encryptedBytes = Protect-ByteArray -Data $bytes -Algorithm $alg -Password $password
            $decryptedBytes = Unprotect-ByteArray -EncryptedData $encryptedBytes -Algorithm $alg -Password $password
            $decryptedString = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
            
            if ($data -eq $decryptedString) {
                Write-Host "    ✓ Byte array test passed (length: $($bytes.Length))" -ForegroundColor Green
            } else {
                Write-Host "    ✗ Byte array test failed (length: $($bytes.Length))" -ForegroundColor Red
                $algorithmPassed = $false
            }
            
        } catch {
            Write-Host "    ✗ Test error: $($_.Exception.Message)" -ForegroundColor Red
            $algorithmPassed = $false
        }
    }
    
    Write-Host "  $alg overall result: $(($algorithmPassed) ? 'PASS' : 'FAIL')" -ForegroundColor $(($algorithmPassed) ? 'Green' : 'Red')
}

# Test 6: Error Handling
Write-Host "`n6. Testing Error Handling:" -ForegroundColor Yellow

# Test wrong password
try {
    $encrypted = Protect-String -PlainText "Test" -Algorithm AES -Password "correct"
    $decrypted = Unprotect-String -EncryptedData $encrypted -Algorithm AES -Password "wrong"
    Write-Host "  ✗ Wrong password test failed - should have thrown an error" -ForegroundColor Red
} catch {
    Write-Host "  ✓ Wrong password correctly threw an error" -ForegroundColor Green
}

# Test algorithm mismatch
try {
    $encrypted = Protect-String -PlainText "Test" -Algorithm AES -Password "test"
    $decrypted = Unprotect-String -EncryptedData $encrypted -Algorithm TripleDES -Password "test"
    Write-Host "  ✗ Algorithm mismatch test failed - should have thrown an error" -ForegroundColor Red
} catch {
    Write-Host "  ✓ Algorithm mismatch correctly threw an error" -ForegroundColor Green
}

# Test Summary
Write-Host "`n=== Test Suite Complete ===" -ForegroundColor Green
Write-Host "Review the results above to ensure all tests passed." -ForegroundColor Yellow
Write-Host "If any tests failed, check the error messages for troubleshooting guidance." -ForegroundColor Yellow
