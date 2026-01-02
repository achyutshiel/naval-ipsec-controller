# Run as Administrator

$LocalIP  = "WINDOWS_IP"
$RemoteIP = "LINUX_IP"
$PSK      = "navalstrongpassword123"

netsh advfirewall consec add rule `
  name="Naval-ESP-IKEv2" `
  endpoint1=$LocalIP `
  endpoint2=$RemoteIP `
  action=requireinrequireout `
  qmsecmethods="ESP:AES256-SHA256" `
  mmsecmethods="DHGroup14" `
  psk=$PSK

Write-Host "ESP tunnel configured"
