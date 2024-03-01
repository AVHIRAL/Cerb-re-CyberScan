# Vérifie si Secure Boot est activé
function Check-SecureBootStatus {
    $secureBootStatus = Confirm-SecureBootUEFI
    if ($secureBootStatus) {
        Write-Host "Secure Boot est activé." -ForegroundColor Green
    } else {
        Write-Host "Secure Boot n'est pas activé. Il est recommandé d'activer Secure Boot dans le BIOS/UEFI." -ForegroundColor Yellow
    }
}

# Vérifie l'état de BitLocker pour la partition système
function Check-BitLockerStatus {
    $bitLockerStatus = Get-BitLockerVolume -MountPoint $env:SystemDrive

    if ($bitLockerStatus.ProtectionStatus -eq 'On') {
        Write-Host "BitLocker est activé pour la partition système." -ForegroundColor Green
    } else {
        Write-Host "BitLocker n'est pas activé pour la partition système. Il est recommandé d'activer BitLocker pour une sécurité accrue." -ForegroundColor Yellow
    }
}

# Exécute les vérifications
Check-SecureBootStatus
Check-BitLockerStatus
