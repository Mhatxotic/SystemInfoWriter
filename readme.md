# System Information Writer…
System Information Writer is a Windows console application that writes the user desired information to the console every second, only mainly useful because its output can be piped to another program and also useful to learn how to query certain aspects of the hardware with Windows.

## Usage…
`Usage: siw[32|64].exe <string>`

You can type any string you want and it will be outputted every second but the main functionality is that the following variables with be dynamically expanded in the output…

| Variable | Function |
| --- | --- |
| `$CR` | Print a carriage return. |
| `$LF` | Print a line feed. |
| `$YT` | Attempt to print the YouTube video you are watching. |
| `$FW` | Print the current title of the foreground window. |
| `$CU` | Print current CPU usage. |
| `$MT` | Show RAM total. |
| `$MFP` | Show RAM free percentage. |
| `$MF` | Show RAM free. |
| `$MUP` | Show RAM used percentage. |
| `$MU` | Show RAM used. |
| `$DF<A-Z>` | Show Drive `A:` to `Z:` available space. |
| `$DU<A-Z>` | Show Drive `A:` to `Z:` used space. |
| `$DT<A-Z>` | Show Drive `A:` to `Z:` total space. |
| `$NCT` | Show current network connection count. |
| `$NCC` | Show current network client connection count. |
| `$NCS` | Show current network server listening count. |
| `$NTI<0-9>` | Show total RX network bytes for interface #`0-9`. |
| `$NTO<0-9>` | Show total TX network bytes for interface #`0-9`. |
| `$NBI<0-9>` | Show current RX network traffic rate for interface #`0-9`. |
| `$NBO<0-9>` | Show current TX network traffic rate for interface #`0-9`. |
| `$A` | Show current time merideum (`AM` or `PM`). |
| `$a` | Show current time merideum (`a` or `p`). |
| `$H` | Show hour in 24 hours format. |
| `$h` | Show hour in 12 hours format. |
| `$I` | Show minute with prepended zero. |
| `$i` | Show minute without prepended zero. |
| `$S` | Show second with prepended zero. |
| `$s` | Show second without prepended zero. |
| `$D` | Show day with prepended zero. |
| `$d` | Show day without prepended zero. |
| `$M` | Show month with prepended zero. |
| `$m` | Show month without prepended zero. |
| `$y` | Show year 00-99. |
| `$Y` | Show full four-digit year. |
