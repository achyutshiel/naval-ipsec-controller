Windows nodes participate as native IPsec ESP peers.
Linux nodes run the controller.

This mirrors real naval mixed-OS deployments.
Verification:
- Windows: Get-NetIPsecMainModeSA
- Linux: ipsec statusall
