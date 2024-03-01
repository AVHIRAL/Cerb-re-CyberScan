# Paramètres
$Threshold = 10
$MonitoringDuration = 10
$BlockingDuration = 3600

# Surveille le trafic réseau
while ($true) {
    $startTime = Get-Date
    $endTime = $startTime.AddSeconds($MonitoringDuration)
    $packets = Get-NetUDPEndpoint -LocalPort 0 -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Group-Object -Property OwningProcess -NoElement |
        Where-Object { $_.Count -ge $Threshold }

    # Bloque les adresses IP suspectes
    foreach ($packet in $packets) {
        $process = Get-Process -Id $packet.Name -ErrorAction SilentlyContinue
        if ($process -ne $null) {
            $remoteAddress = $process.Connections.RemoteAddress.IPAddressToString
            $ruleName = "Block-IP-$remoteAddress"
            if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
                Write-Host "Bloquant l'adresse IP $remoteAddress"
                New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -RemoteAddress $remoteAddress -Action Block
                Start-Sleep -Seconds $BlockingDuration
                Write-Host "Débloquant l'adresse IP $remoteAddress"
                Remove-NetFirewallRule -DisplayName $ruleName
            }
        }
    }

    # Attend jusqu'à la fin de la période de surveillance
    $sleepDuration = ($endTime - (Get-Date)).TotalSeconds
    if ($sleepDuration -gt 0) {
        Start-Sleep -Seconds $sleepDuration
    }
}
