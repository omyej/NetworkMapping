function Global:Ping-IPRange {
    <#
    .SYNOPSIS
        Sends ICMP echo request packets to a range of IPv4 addresses between two given addresses.

    .DESCRIPTION
        This function lets you sends ICMP echo request packets ("pings") to 
        a range of IPv4 addresses using an asynchronous method.

        Therefore this technique is very fast but comes with a warning.
        Ping sweeping a large subnet or network with many swithes may result in 
        a peak of broadcast traffic.
        Use the -Interval parameter to adjust the time between each ping request.
        For example, an interval of 60 milliseconds is suitable for wireless networks.
        The RawOutput parameter switches the output to an unformated
        [System.Net.NetworkInformation.PingReply[]].

    .INPUTS
        None
        You cannot pipe input to this funcion.

    .OUTPUTS
        The function only returns output from successful pings.

        Type: System.Net.NetworkInformation.PingReply

        The RawOutput parameter switches the output to an unformated
        [System.Net.NetworkInformation.PingReply[]].

    .NOTES
        Author  : G.A.F.F. Jakobs
        Created : August 30, 2014
        Version : 6

    .EXAMPLE
        Ping-IPRange -StartAddress 192.168.1.1 -EndAddress 192.168.1.254 -Interval 20

        IPAddress                                 Bytes                     Ttl           ResponseTime
        ---------                                 -----                     ---           ------------
        192.168.1.41                                 32                      64                    371
        192.168.1.57                                 32                     128                      0
        192.168.1.64                                 32                     128                      1
        192.168.1.63                                 32                      64                     88
        192.168.1.254                                32                      64                      0

        In this example all the ip addresses between 192.168.1.1 and 192.168.1.254 are pinged using 
        a 20 millisecond interval between each request.
        All the addresses that reply the ping request are listed.

    .LINK
        http://gallery.technet.microsoft.com/Fast-asynchronous-ping-IP-d0a5cf0e

    #>
    [CmdletBinding(ConfirmImpact='Low')]
    Param(
        [parameter(Mandatory = $true, Position = 0)]
        [System.Net.IPAddress]$StartAddress,
        [parameter(Mandatory = $true, Position = 1)]
        [System.Net.IPAddress]$EndAddress,
        [int]$Interval = 30,
        [Switch]$RawOutput = $false
    )

    $timeout = 2000

    function New-Range ($start, $end) {

        [byte[]]$BySt = $start.GetAddressBytes()
        [Array]::Reverse($BySt)
        [byte[]]$ByEn = $end.GetAddressBytes()
        [Array]::Reverse($ByEn)
        $i1 = [System.BitConverter]::ToUInt32($BySt,0)
        $i2 = [System.BitConverter]::ToUInt32($ByEn,0)
        for($x = $i1;$x -le $i2;$x++){
            $ip = ([System.Net.IPAddress]$x).GetAddressBytes()
            [Array]::Reverse($ip)
            [System.Net.IPAddress]::Parse($($ip -join '.'))
        }
    }

    $IPrange = New-Range $StartAddress $EndAddress
    $IpTotal = $IPrange.Count

    Get-Event -SourceIdentifier "ID-Ping*" | Remove-Event
    Get-EventSubscriber -SourceIdentifier "ID-Ping*" | Unregister-Event

    $IPrange | foreach{
        [string]$VarName = "Ping_" + $_.Address
        New-Variable -Name $VarName -Value (New-Object System.Net.NetworkInformation.Ping)
        Register-ObjectEvent -InputObject (Get-Variable $VarName -ValueOnly) -EventName PingCompleted -SourceIdentifier "ID-$VarName"
        (Get-Variable $VarName -ValueOnly).SendAsync($_,$timeout,$VarName)
        Remove-Variable $VarName

        try{
            $pending = (Get-Event -SourceIdentifier "ID-Ping*").Count
        }catch [System.InvalidOperationException]{}
        $index = [array]::indexof($IPrange,$_)
        Write-Progress -Activity "Sending ping to" -Id 1 -status $_.IPAddressToString -PercentComplete (($index / $IpTotal)  * 100)
        Write-Progress -Activity "ICMP requests pending" -Id 2 -ParentId 1 -Status ($index - $pending) -PercentComplete (($index - $pending)/$IpTotal * 100)
        Start-Sleep -Milliseconds $Interval
    }

    Write-Progress -Activity "Done sending ping requests" -Id 1 -Status 'Waiting' -PercentComplete 100 
    
    While($pending -lt $IpTotal){
        Wait-Event -SourceIdentifier "ID-Ping*" | Out-Null
        Start-Sleep -Milliseconds 10
        $pending = (Get-Event -SourceIdentifier "ID-Ping*").Count
        Write-Progress -Activity "ICMP requests pending" -Id 2 -ParentId 1 -Status ($IpTotal - $pending) -PercentComplete (($IpTotal - $pending)/$IpTotal * 100)
    }

    if($RawOutput){
        $Reply = Get-Event -SourceIdentifier "ID-Ping*" | ForEach { 
            If($_.SourceEventArgs.Reply.Status -eq "Success"){
                $_.SourceEventArgs.Reply
            }
            Unregister-Event $_.SourceIdentifier
            Remove-Event $_.SourceIdentifier
        }

    }else{
        $Reply = Get-Event -SourceIdentifier "ID-Ping*" | ForEach { 
            If($_.SourceEventArgs.Reply.Status -eq "Success"){
                $_.SourceEventArgs.Reply | select @{
                      Name="IPAddress"   ; Expression={$_.Address}},
                    @{Name="Bytes"       ; Expression={$_.Buffer.Length}},
                    @{Name="Ttl"         ; Expression={$_.Options.Ttl}},
                    @{Name="ResponseTime"; Expression={$_.RoundtripTime}}
            }
            Unregister-Event $_.SourceIdentifier
            Remove-Event $_.SourceIdentifier
        }
    }

    if($Reply -eq $Null){
        Write-Verbose "Ping-IPrange : No ip address responded" -Verbose
    }
    
    Write-Host "Ping Replies:"
    foreach($i in $Reply){
        Write-Host $i.IPAddress
    }
    write-Host ""


    ##############  Traceroute #################
    Write-Host "TraceRoute:"
    Foreach ($ip in $Reply) {
        $p = Test-NetConnection -TraceRoute $ip.IPAddress
        $dns = Resolve-DnsName -LlmnrFallback -NetbiosFallback -QuickTimeout $ip.IPAddress -ErrorAction SilentlyContinue
        $ip | add-member -membertype noteproperty -name TraceRoute -value $p.TraceRoute
        $ip | add-member -membertype noteproperty -name OpenPorts -value @()
        $ip | add-member -membertype noteproperty -name HostName -value $dns.NameHost
        $outString = "$($ip.IPAddress) ($($dns.NameHost)):  $($ip.TraceRoute)"
        Write-Host $outString
    }
    write-Host ""

    ############# Port Scanner ################

    $port_dict = @{
        "80"="http"
        "23"="telnet"
        "443"="https"
        "21"="ftp"
        "22"="ssh"
        "25"="smtp"
        "3389"="ms-wbt-server"
        "110"="pop3"
        "445"="microsoft-ds"
        "139"="netbios-ssn"
        "143"="imap"
        "53"="domain"
        "135"="msrpc"
        "3306"="mysql"
        "8080"="http-proxy"
        "1723"="pptp"
        "111"="rpcbind"
        "995"="pop3s"
        "993"="imaps"
        "5900"="vnc"
        "1025"="NFS-or-IIS"
        "587"="submission"
        "8888"="sun-answerbook"
        "199"="smux"
        "1720"="h323q931"
        "465"="smtps"
        "548"="afp"
        "113"="ident"
        "81"="hosts2-ns"
        "6001"="X11:1"
        "10000"="snet-sensor-mgmt"
        "514"="shell"
        "5060"="sip"
        "179"="bgp"
        "1026"="LSA-or-nterm"
        "2000"="cisco-sccp"
        "8443"="https-alt"
        "8000"="http-alt"
        "32768"="filenet-tms"
        "554"="rtsp"
        "26"="rsftp"
        "1433"="ms-sql-s"
        "49152"="unknown"
        "2001"="dc"
        "515"="printer"
        "8008"="http"
        "49154"="unknown"
        "1027"="IIS"
        "5666"="nrpe"
        "646"="ldp"
        "5000"="upnp"
        "5631"="pcanywheredata"
        "631"="ipp"
        "49153"="unknown"
        "8081"="blackice-icecap"
        "2049"="nfs"
        "88"="kerberos-sec"
        "79"="finger"
        "5800"="vnc-http"
        "106"="pop3pw"
        "2121"="ccproxy-ftp"
        "1110"="nfsd-status"
        "49155"="unknown"
        "6000"="X11"
        "513"="login"
        "990"="ftps"
        "5357"="wsdapi"
        "427"="svrloc"
        "49156"="unknown"
        "543"="klogin"
        "544"="kshell"
        "5101"="admdog"
        "144"="news"
        "7"="echo"
        "389"="ldap"
        "8009"="ajp13"
        "3128"="squid-http"
        "444"="snpp"
        "9999"="abyss"
        "5009"="airport-admin"
        "7070"="realserver"
        "5190"="aol"
        "3000"="ppp"
        "5432"="postgresql"
        "1900"="upnp"
        "3986"="mapper-ws_ethd"
        "13"="daytime"
        "1029"="ms-lsa"
        "9"="discard"
        "5051"="ida-agent"
        "6646"="unknown"
        "49157"="unknown"
        "1028"="unknown"
        "873"="rsync"
        "1755"="wms"
        "2717"="pn-requester"
        "4899"="radmin"
        "9100"="jetdirect"
        "119"="nntp"
        "37"="time"
        }


    $ports = $port_dict.Keys

    foreach ($ip in $Reply) {
        $target = $ip.IPAddress
        foreach ($port in $ports) {
            $obj = new-Object system.Net.Sockets.TcpClient
            $connect = $obj.BeginConnect($target,$port,$null,$null)
            $Wait = $connect.AsyncWaitHandle.WaitOne(100,$false)

            If (-Not $Wait) {
                #write-host $target 'port' $port 'Closed - Timeout'
            } else {
                $value = "Open"
                write-host $target 'port' $port $value
                $ip.OpenPorts += $port
            }
        }
    }
    return $Reply
}


$results = Ping-IPRange -StartAddress 131.5.54.100 -EndAddress 131.5.54.101

$results | Export-Clixml ./ScanResults.xml