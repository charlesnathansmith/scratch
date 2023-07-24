# Get mac address
$mac_ascii = ((Get-NetAdapter -Physical).MacAddress) -replace '-'
$mac_bytes = [byte[]] -split ($mac_ascii -replace '..', '0x$& ')

# Calculate registry value
for($i=0; $i -lt $mac_bytes.count; $i++)
{
    $mac_bytes[$i] = $mac_bytes[$i] -bxor 0x99
    $swap_rtl = ($mac_bytes[$i] -band 0xf) -shl 4
    $swap_ltr = ($mac_bytes[$i] -band 0xf0) -shr 4
    $mac_bytes[$i] = $swap_rtl + $swap_ltr
}

# Save registry value - Writing to HKLM requires admin
Set-ItemProperty "HKLM:SOFTWARE\CSManfSim\Contact\Network\Web" MAC $mac_bytes -type binary
