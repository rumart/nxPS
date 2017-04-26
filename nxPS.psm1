function Invoke-NXApiRequest{
[CmdletBinding()]
param(
    $NXConnection,
    [Parameter(Mandatory=$false)]
    [ValidateSet("SHOW","CONFIGURE")]
    [string]
    $Method = "SHOW",
    [string]
    $Resource
)
    BEGIN {
        if(!$NXConnection){
            $NXConnection = $Global:nxsessioncookie
        }

        if($Method = "SHOW"){
            $cliType = "cli_show"
            $command = "show "
        }
        elseif($Method = "CONFIGURE"){
            $cliType = "cli_conf"

        }
        $command += $Resource
    }
    PROCESS {

    $body = @"
{
"ins_api": {
"version": "1.2",
"type": "$cliType",
"chunk": "0",
"sid": "1",
"input": "$command",
"output_format": "xml"
}
}
"@

       
        $result = Invoke-WebRequest -Uri $NXConnection.Uri -Body $body -Headers $NXConnection.Header -Credential $NXConnection.Credential -Method Post -UseBasicParsing
        $xmlRes = [xml]$result.Content

        $returncode = $xmlres.ins_api.outputs.output.code

        if($returncode -eq 200){
            $xmlBody = $xmlRes.ins_api.outputs.output.body    
        }
        elseif($returncode -eq 400){
            $xmlbody = $xmlRes.ins_api.outputs.output.clierror
        }
        elseif($returncode -eq 501){
            $xmlbody = $xmlRes.ins_api.outputs.output.clierror
        }
        else{
            throw "ERROR -- Error while retrieving information"
        }

        $xmlBody

    }
    END {
    
    }

}

function New-NXConnection {
<#
    .SYNOPSIS
        Creates a connection object to the specified Nexus switch
    .DESCRIPTION
        The function connects to the specified Nexus switch with the
        given username and password, or credential object, 
        and retrieves a session key. By default this session cookie will
        expire after 10 minutes.
        The output of the function will include the base uri and the credentials for
        use in subsequent calls to the Nexus switch
    .PARAMETER Hostname
        Hostname or IP address of the switch
    .PARAMETER Scheme
        Protocol for the API (HTTP or HTTPS)
    .PARAMETER Port
        Port for the API on the switch
    .PARAMETER Username
        Username for the connection
    .PARAMETER Credential
        PSCredential object for the connection
    .EXAMPLE
        New-NXConnection -Hostname 10.10.10.10 -Port 443 -Username nxapi
        This will prompt for the password to the corresponding user and connect to
        the switch on the given IP address and port
    .EXAMPLE
        New-NXConnection -Hostname 10.10.10.10 -Port 443 -Credential $cred
        This will use a predefined credential object and connect to
        the switch on the given IP address and port
    .NOTES
        NAME: New-NXConnection
        AUTHOR: Rudi Martinsen
        CREATED: 27/06-2016
        VERSION: 0.5.0
        REVISED: 26/04-2017
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true,Position=0)]
    [Alias('IP')]
    $Hostname,
    [ValidateSet("HTTP","HTTPS")]
    $Scheme = "HTTPS",
    [Parameter(Mandatory=$true)]
    [int]
    $Port,
    [Parameter(ParameterSetName='Login',Mandatory=$true)]
    [string]
    $Username,
    [Parameter(ParameterSetName='Credential',Mandatory=$true)]
    $Credential
)

add-type @" 
using System.Net; 
using System.Security.Cryptography.X509Certificates; 
public class TrustAllCertsPolicy : ICertificatePolicy { 
    public bool CheckValidationResult( 
        ServicePoint srvPoint, X509Certificate certificate, 
        WebRequest request, int certificateProblem) { 
        return true; 
    } 
} 
"@  
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy -ErrorAction SilentlyContinue -WarningAction SilentlyContinue 

    $headers = @{}
    $headers["Accept"] = "application/json"

    
$body = @"
{
"ins_api": {
"version": "1.2",
"type": "cli_show",
"chunk": "0",
"sid": "1",
"input": "show version",
"output_format": "json"
}
}
"@

    $uri = $Scheme + "://$Hostname" + ":" + $port + "/ins"
    
    if($Credential){
        Write-Verbose "Credential object passed"
    }
    else{
        $credential = Get-Credential -Message "Please enter username and password" -UserName $Username
    }

    $result = Invoke-WebRequest -Uri $uri -Method Post -ContentType "application/json" -Body $body -Headers $headers -Credential $credential -UseBasicParsing

    $head = $headers
    $head["Set-Cookie"] = $result.Headers.'Set-Cookie'
    
    $sessionCookie = New-Object -TypeName PSCustomObject
    $sessionCookie | Add-Member -MemberType NoteProperty -Name Uri -Value $uri
    $sessionCookie | Add-Member -MemberType NoteProperty -Name Header -Value $head
    $sessionCookie | Add-Member -MemberType NoteProperty -Name Credential -Value $credential
    
    $global:nxhost = $Hostname
    $global:nxsessioncookie = $sessionCookie
    
    $sessionCookie
}

function Get-NXInfo {
<#
    .SYNOPSIS
        Retrieves information about the specified Nexus switch
    .DESCRIPTION
        The function connects to the specified Nexus switch with the
        given connection object and retrieves general information 
        about the switch
        Cli command equivalent: show version
    .PARAMETER Connection
        Connection object from the New-NXConnection function
    .EXAMPLE
        Get-NXInfo -Connection $connection
        This will connect to the switch with the session information stored
        in the connection object and display general info
    .NOTES
        NAME: Get-NXInfo
        AUTHOR: Rudi Martinsen
        CREATED: 27/06-2016
        VERSION: 0.3.0
        REVISED: 01/12-2016
#>
    [CmdLetBinding()]
    param(
        $Connection #= $(throw "Connection object missing, run New-NXConnection")
    )

    $Resource = "version"

    $xmlbody = Invoke-NXApiRequest -NXConnection $Connection -Method SHOW -Resource $Resource

    if($xmlBody.mem_type -ne 'kB'){
        if($xmlBody.mem_type -eq 'mB'){
            $memory = $xmlBody.memory * 1024
        }
        if($xmlBody.mem_type -eq 'GB'){
            $memory = ($xmlBody.memory * 1024) * 1024
        }
    }
    else{
        $memory = $xmlBody.memory
    }

    if($connection){
        $connObj = $Connection
    }
    else{
        $connObj = $Global:nxsessioncookie
    }

    #$IP = $connObj.Uri.replace("https://",'').split(":")[0]

    $outputObj = New-Object -TypeName PsCustomObject
    $outputObj | Add-Member -MemberType NoteProperty -Name HostName -Value $xmlBody.host_name
    #$outputObj | Add-Member -MemberType NoteProperty -Name IP -Value $IP
    $outputObj | Add-Member -MemberType NoteProperty -Name Chassis -Value $xmlBody.chassis_id
    $outputObj | Add-Member -MemberType NoteProperty -Name Module -Value $xmlBody.module_id
    $outputObj | Add-Member -MemberType NoteProperty -Name Bios_Version -Value $xmlBody.bios_ver_str
    $outputObj | Add-Member -MemberType NoteProperty -Name System_Version -Value $xmlBody.sys_ver_str
    $outputObj | Add-Member -MemberType NoteProperty -Name CPU -Value $xmlBody.cpu_name
    $outputObj | Add-Member -MemberType NoteProperty -Name MemkB -Value $xmlBody.memory
    $outputObj | Add-Member -MemberType NoteProperty -Name StartTime -Value $xmlBody.rr_ctime.TrimStart()

    $outputObj

}

function Get-NXNeighbor {
<#
    .SYNOPSIS
        Displays information about the neighbors of the Nexus switch
    .DESCRIPTION
        The function connects to the specified Nexus switch with the
        given connection object and retrieves neighbor information 
        about the switch
        Cli command equivalent: show cdp neighbor
    .PARAMETER Connection
        Connection object from the New-NXConnection function
    .EXAMPLE
        Get-NXNeighbor -Connection $connection
        This will connect to the switch with the session information stored
        in the connection object and display neighbor info
    .NOTES
        NAME: Get-NXNeighbor
        AUTHOR: Rudi Martinsen
        CREATED: 27/06-2016
        VERSION: 0.2.0
        REVISED: 30/11-2016
#>
    [CmdLetBinding()]
    param(
        $Connection #= $(throw "Connection object missing, run New-NXConnection")
    )
    
    $Resource = "cdp neighbor"
    
    $xmlbody = Invoke-NXApiRequest -NXConnection $Connection -Method SHOW -Resource $Resource

    $output = @()
    
    foreach($row in $xmlBody.TABLE_cdp_neighbor_brief_info.ROW_cdp_neighbor_brief_info){
        
        $rowObj = New-Object -TypeName PSCustomObject
        $rowObj | Add-Member -MemberType NoteProperty -Name Device -Value $row.device_id
        $rowObj | Add-Member -MemberType NoteProperty -Name Interface -Value $row.intf_id
        $rowObj | Add-Member -MemberType NoteProperty -Name Capability -Value $row.capability
        $rowObj | Add-Member -MemberType NoteProperty -Name Platform -Value $row.platform_id
        $rowObj | Add-Member -MemberType NoteProperty -Name Port -Value $row.port_id

        $output += $rowObj
    }

    $output
    
}

function Get-NXPortProfile {
<#
    .SYNOPSIS
        Displays information about the port profile(s) of the Nexus switch
    .DESCRIPTION
        The function connects to the specified Nexus switch with the
        given connection object and retrieves port profile information 
        from the switch
        Cli command equivalent: show port-profile (name $profile)
    .PARAMETER Connection
        Connection object from the New-NXConnection function
    .PARAMETER Profile
        Optional parameter for querying a single profile
    .EXAMPLE
        Get-NXPortProfile -Connection $connection
        This will connect to the switch with the session information stored
        in the connection object and display all port profiles
    .EXAMPLE
        Get-NXPortProfile -Connection $connection -Profile profile1
        This will connect to the switch with the session information stored
        in the connection object and display information about 
        the profile: profile1 if found
    .NOTES
        NAME: Get-NXPortProfile
        AUTHOR: Rudi Martinsen
        CREATED: 27/06-2016
        VERSION: 0.3.0
        REVISED: 24/04-2017
#>
    [CmdLetBinding()]
    param(
        $Connection, #= $(throw "Connection object missing, run New-NXConnection"),
        [string]
        [Alias('Profile')]
        $PortProfile
    )

    $Resource = "port-profile"
    if($PortProfile){
        $Resource += " name $PortProfile"
    }

    $xmlRes = Invoke-NXApiRequest -NXConnection $Connection -Method SHOW -Resource $Resource
    $profiles = $xmlRes.profile_name
    $profileObjects = @()
    
    foreach($profile in $profiles){
 
        $resource = "port-profile name $profile"
        $xmlBodyProf = Invoke-NXApiRequest -NXConnection $Connection -Method SHOW -Resource $resource
        
        $portMode = $xmlBodyProf.profile_cfg[0] -replace "switchport mode ",""
        $vlans = @()
        foreach($vl in $xmlBodyProf.profile_cfg){
            if($vl -like "switchport trunk allowed*"){
                $vl = $vl -replace "switchport trunk allowed vlan ",""
                $vl = $vl -split ","
                $vl = $vl.trim()
                
                foreach($v in $vl){
                    if($v -match '-'){
                        $vArr = $v.Split('-')
                        $vlans += ($vArr[0])..($vArr[1])
                    }
                    else{
                        $vlans += $v
                    }
                }
            }
        }

        #Strange return value from XML when there is no interfaces..
        if($xmlBodyProf.intf -eq "?#:0x4e4f4e45"){
            $interfaces = $null
        }
        else{
            $interfaces = $xmlBodyProf.intf
        }

        $profileObj = New-Object -TypeName PsCustomObject
        $profileObj | Add-Member -MemberType NoteProperty -Name Profile -Value $xmlBodyProf.profile_name
        $profileObj | Add-Member -MemberType NoteProperty -Name Desc -Value $xmlBodyProf.desc
        $profileObj | Add-Member -MemberType NoteProperty -Name Status -Value $xmlBodyProf.status
        $profileObj | Add-Member -MemberType NoteProperty -Name PortMode -Value $portMode
        $profileObj | Add-Member -MemberType NoteProperty -Name Vlans -Value $vlans
        $profileObj | Add-Member -MemberType NoteProperty -Name Interfaces -Value $interfaces
        $profileObjects += $profileObj

    }

    $profileObjects

}

function Get-NXInterface {
<#
    .SYNOPSIS
        Displays information about the interface(s) of the Nexus switch
    .DESCRIPTION
        The function connects to the specified Nexus switch with the
        given connection object and retrieves interface information 
        from the switch
        Cli command equivalent: show interface ($interface)
    .PARAMETER Connection
        Connection object from the New-NXConnection function
    .PARAMETER Interface
        Interface to check
    .PARAMETER State
        Filter output on interface state
    .EXAMPLE
        Get-NXInterface -Connection $connection
        This will connect to the switch with the session information stored
        in the connection object and display all port profiles
    .EXAMPLE
        Get-NXPortProfile -Connection $connection -Interface "Ethernet101/1/1"
        Displays information about the specified interface, if found
    .NOTES
        NAME: Get-NXInterface
        AUTHOR: Rudi Martinsen
        CREATED: 27/06-2016
        VERSION: 0.3.0
        REVISED: 24/04-2017
#>
    [CmdLetBinding()]
    param(
        $Connection, #= $(throw "Connection object missing, run New-NXConnection"),
        [string]
        $Interface,
        [ValidateSet("Up","Down","All")]
        $State = "All"
    )

    $Resource = "interface"

    if($Interface){
        $Resource += " $interface"
    }

    $xmlbody = Invoke-NXApiRequest -NXConnection $Connection -Method SHOW -Resource $Resource
    
    $output = @()
    
    foreach($row in $xmlBody.TABLE_interface.ROW_interface){
        
        $rowObj = New-Object -TypeName PSCustomObject
        $rowObj | Add-Member -MemberType NoteProperty -Name Interface -Value $row.interface
        $rowObj | Add-Member -MemberType NoteProperty -Name State -Value $row.state
        $rowObj | Add-Member -MemberType NoteProperty -Name HW_Desc -Value $row.eth_hw_desc
        $rowObj | Add-Member -MemberType NoteProperty -Name HW_Address -Value $row.eth_hw_addr
        $rowObj | Add-Member -MemberType NoteProperty -Name Desc -Value $row.desc
        $rowObj | Add-Member -MemberType NoteProperty -Name Mode -Value $row.eth_mode
        $rowObj | Add-Member -MemberType NoteProperty -Name Link_Flapped -Value $row.eth_link_flapped
        $rowObj | Add-Member -MemberType NoteProperty -Name Eth_InPkts -Value $row.eth_inpkts
        $rowObj | Add-Member -MemberType NoteProperty -Name Eth_InBytes -Value $row.eth_inbytes
        $rowObj | Add-Member -MemberType NoteProperty -Name Eth_OutPkts -Value $row.eth_outpkts
        $rowObj | Add-Member -MemberType NoteProperty -Name Eth_OutBytes -Value $row.eth_outbytes

        $output += $rowObj
    }

    if($State -eq "Up"){
        $output | Where-Object {$_.State -eq "Up"}
    }
    elseif($State -eq "Down"){
        $output | Where-Object {$_.State -eq "Down"}
    }
    else{
        $output
    }
    
}

function Get-NXVlan {
<#
    .SYNOPSIS
        Displays information about the Vlan(s) of the Nexus switch
    .DESCRIPTION
        The function connects to the specified Nexus switch with the
        given connection object and retrieves vlan information 
        from the switch
        Cli command equivalent: show vlan (id $vlan)
    .PARAMETER Connection
        Connection object from the New-NXConnection function
    .PARAMETER Vlan
        Vlan Id to check
    .EXAMPLE
        Get-NXVlan -Connection $connection
        This will connect to the switch with the session information stored
        in the connection object and display all port profiles
    .EXAMPLE
        Get-NXVlan -Connection $connection -Vlan 123
        Displays information about the specified vlan id, if found
    .NOTES
        NAME: Get-NXVlan
        AUTHOR: Rudi Martinsen
        CREATED: 27/06-2016
        VERSION: 0.4.0
        REVISED: 24/04-2017
#>
    [CmdLetBinding()]
    param(
        $Connection, #= $(throw "Connection object missing, run New-NXConnection"),
        $Vlan
    )
    $Resource = "vlan"

    if($vlan){
        $Resource += " id $Vlan"
    }


    $xmlBody = Invoke-NXApiRequest -NXConnection $Connection -Method SHOW -Resource $Resource
    
    $output = @()
    if($vlan){
        $tblHead = $xmlBody.TABLE_vlanbriefid.ROW_vlanbriefid
    }
    else{
        $tblHead = $xmlBody.TABLE_vlanbrief.ROW_vlanbrief
        
    }
    foreach($row in $tblHead){
            $ifs = $row.'vlanshowplist-ifidx' -split ","
            $rowObj = New-Object -TypeName PSCustomObject
            $rowObj | Add-Member -MemberType NoteProperty -Name VlanId -Value $row.'vlanshowbr-vlanid'
            $rowObj | Add-Member -MemberType NoteProperty -Name Name -Value $row.'vlanshowbr-vlanname'
            $rowObj | Add-Member -MemberType NoteProperty -Name State -Value $row.'vlanshowbr-vlanstate'
            $rowObj | Add-Member -MemberType NoteProperty -Name Shut_state -Value $row.'vlanshowbr-shutstate'
            $rowObj | Add-Member -MemberType NoteProperty -Name Interface -Value $ifs

            $output += $rowObj
    }

    $output
    
}

function Get-NXDeviceAlias {
<#
    .SYNOPSIS
        Displays device-aliases configured on the Nexus switch
    .DESCRIPTION
        The function connects to the specified Nexus switch with the
        given connection object and retrieves the device aliases configured
        on the switch
        Cli command equivalent: show device-alias database | name $name | pwwn $pwwn
    .PARAMETER Connection
        Connection object from the New-NXConnection function
    .PARAMETER Name
        Optional parameter for querying a single alias by name
    .PARAMETER Pwwn
        Optional parameter for querying a single alias by pwwn
    .EXAMPLE
        Get-NXDeviceAlias -Connection $connection
        This will connect to the switch with the session information stored
        in the connection object and display all device aliases
    .EXAMPLE
        Get-NXDeviceAlias -Connection $connection -Name host1
        This will display the alias for the given host
    .EXAMPLE
        Get-NXDeviceAlias -Connection $connection -Pwwn 11:11:11:11:11:11:11:11
        This will display the alias for the given pwwn
    .NOTES
        NAME: Get-NXDeviceAlias
        AUTHOR: Rudi Martinsen
        CREATED: 27/06-2016
        VERSION: 0.2.1
        REVISED: 19/04-2017
#>
[CmdLetBinding(DefaultParameterSetName="All")]
    param(
        $Connection, #= $(throw "Connection object missing, run New-NXConnection"),
        [Parameter(Mandatory=$false,ParameterSetName='AliasName')]
        [Alias('Alias')]
        [string]
        $Name,
        [Parameter(Mandatory=$false,ParameterSetName='Pwwn')]
        [Alias('WWN')]
        [string]
        $Pwwn
    )

    $Resource = "device-alias"
    if($Name){
        $Resource += " name $name"
    }
    elseif($Pwwn){
        $Resource += " pwwn $pwwn"
    }
    else{
        $Resource += " database"
    }
    
    $aliases = Invoke-NXApiRequest -NXConnection $Connection -Method SHOW -Resource $Resource

    $aliasObjects = @()

    $lines = $aliases -split('[\r\n]')
    foreach($line in $lines | Where-Object {$_ -like "device-alias name*"}){
        
        $lineArr = $line.Replace("device-alias name ","").replace("pwwn ","").split(" ")
        
        $aliasObj = New-Object PSCustomObject
        $aliasObj | Add-Member -MemberType NoteProperty -Name Name -Value $lineArr[0]
        $aliasObj | Add-Member -MemberType NoteProperty -Name Pwwn -Value $lineArr[1]
        $aliasObjects += $aliasObj
    }

    $aliasObjects

}

function Get-NXVsan {
<#
    .SYNOPSIS
        Displays Vsan(s) configured on the Nexus switch
    .DESCRIPTION
        The function connects to the specified Nexus switch with the
        given connection object and retrieves information about the
        vsan(s) configured on the switch
        Cli command equivalent: show vsan ($id)
    .PARAMETER Connection
        Connection object from the New-NXConnection function
    .PARAMETER Id
        Optional parameter for querying a single vlan by id
    .EXAMPLE
        Get-NXVsan -Connection $connection
        This will connect to the switch with the session information stored
        in the connection object and display all vsans
    .EXAMPLE
        Get-NXVsan -Connection $connection -VsanId 123
        This will display information about the given vsan id
    .NOTES
        NAME: Get-NXVsan
        AUTHOR: Rudi Martinsen
        CREATED: 27/06-2016
        VERSION: 0.2.0
        REVISED: 01/12-2016
#>
[CmdLetBinding(DefaultParameterSetName="All")]
    param(
        $Connection,# = $(throw "Connection object missing, run New-NXConnection"),
        [Parameter(Mandatory=$false,ParameterSetName='AliasName')]
        [Alias('Id')]
        [string]
        $VsanId
    )

    $Resource = "vsan"

    if($VsanId){
        $Resource += " $vsanId"
    }

    $vsans = Invoke-NXApiRequest -NXConnection $Connection -Method SHOW -Resource $Resource
    
    $vsanObjects = @()
    $i = 0
    $lines = $vsans -split('[\r\n]')

    $vsanTbl = @{}

    foreach($line in $lines){
        $i++
        if($line -like "vsan*information"){
            $vsanTbl.Add($line.Split(" ")[1],$i)
        }
    }

    foreach($row in $vsanTbl.GetEnumerator()){
        $vsLine = $lines[$row.Value]
        $name = $vsLine -match 'name:(\w*-?\w*\-?\w*)'
        $name = $matches[1]
        $state = $vsLine -match 'state:(\w*)'
        $state = $matches[1]

        $vsanObj = New-Object PSCustomObject
        $vsanObj | Add-Member -MemberType NoteProperty -Name VsanId -Value $row.Name
        $vsanObj | Add-Member -MemberType NoteProperty -Name Name -Value $name
        $vsanObj | Add-Member -MemberType NoteProperty -Name State -Value $state
        $vsanObjects += $vsanObj
    }

    $vsanObjects

}

function Get-NXZone {
<#
    .SYNOPSIS
        Displays Zone(s) configured on the Nexus switch
    .DESCRIPTION
        The function connects to the specified Nexus switch with the
        given connection object and retrieves information about the
        Zone(s) configured on the switch
        Cli command equivalent: show zone
    .PARAMETER Connection
        Connection object from the New-NXConnection function
    .PARAMETER Name
        Retrieves the specified zone, if found
    .EXAMPLE
        Get-NXZone -Connection $connection
        This will connect to the switch with the session information stored
        in the connection object and display all zones
    .NOTES
        NAME: Get-NXZone
        AUTHOR: Rudi Martinsen
        CREATED: 27/06-2016
        VERSION: 0.3.0
        REVISED: 24/04-2017
#>
[CmdLetBinding(DefaultParameterSetName="All")]
    param(
        $Connection,
        [Parameter(ParameterSetName="Name")]
        [Alias("Zone")]
        $Name,
        [Parameter(ParameterSetName="Vsan")]
        [Int]
        $Vsan
    )

    $Resource = "zone"

    if($Name){
        $Resource += " name " + $Name
    }

    if($Vsan){
        $Resource += " vsan " + $Vsan
    }

    $zones = Invoke-NXApiRequest -NXConnection $Connection -Method SHOW -Resource $Resource
    
    $zoneObjects = @()
    $i = 0
    $lines = $zones -split('[\r\n]')

    $zoneTbl = @{}

    foreach($line in $lines){
        $i++
        if($line -like "zone name*"){
            $zoneTbl.Add($line.replace("zone name ",""),$i)
        }
    }

    foreach($row in $zoneTbl.GetEnumerator()){
        $split = $row.Name.Split("vsan")
        $name = $split[0]
        $vsanid = $split[($split.Length)-1].trim()
                
        $aliases = @()
                
        if($lines[$row.Value] -like "*device-alias*"){
            for($y=$row.value;$y -le $row.value+1;$y++){
                $alias = $lines[$y].Replace("device-alias","").trim()
                $aliases += $alias
            }
        }


        $zoneObj = New-Object PSCustomObject
        $zoneObj | Add-Member -MemberType NoteProperty -Name Name -Value $name
        $zoneObj | Add-Member -MemberType NoteProperty -Name VsanId -Value $vsanid
        $zoneObj | Add-Member -MemberType NoteProperty -Name DeviceAliases -Value $aliases
        $zoneObjects += $zoneObj
    }

    $zoneObjects

}

function Get-NXFex {
<#
    .SYNOPSIS
        Displays Fex(es) configured on the Nexus switch
    .DESCRIPTION
        The function connects to the specified Nexus switch with the
        given connection object and retrieves information about the
        Fex(es) configured on the switch
        Cli command equivalent: show fex
    .PARAMETER Connection
        Connection object from the New-NXConnection function
    .EXAMPLE
        Get-NXFex -Connection $connection
        This will connect to the switch with the session information stored
        in the connection object and display all zones
    .NOTES
        NAME: Get-NXFex
        AUTHOR: Rudi Martinsen
        CREATED: 29/06-2016
        VERSION: 0.2.0
        REVISED: 01/12-2016
#>
[CmdLetBinding(DefaultParameterSetName="All")]
    param(
        $Connection #= $(throw "Connection object missing, run New-NXConnection")
    )

    $Resource = "fex"

    $xmlBody = Invoke-NXApiRequest -NXConnection $Connection -Method SHOW -Resource $Resource

    $output = @()
    if($xmlBody.TABLE_fex.ROW_fex){
        foreach($row in $xmlBody.TABLE_fex.ROW_fex){
        
            $rowObj = New-Object -TypeName PSCustomObject
            $rowObj | Add-Member -MemberType NoteProperty -Name FexNumber -Value $row.fex_number
            $rowObj | Add-Member -MemberType NoteProperty -Name Model -Value $row.fex_model
            $rowObj | Add-Member -MemberType NoteProperty -Name Serial -Value $row.fex_ser
            $rowObj | Add-Member -MemberType NoteProperty -Name Description -Value $row.fex_descr
            $rowObj | Add-Member -MemberType NoteProperty -Name State -Value $row.fex_state
            $rowObj | Add-Member -MemberType NoteProperty -Name Chas_Serial -Value $row.chas_ser
            $rowObj | Add-Member -MemberType NoteProperty -Name Vendor -Value $row.chas_vendor

            $output += $rowObj
        }
    }
    
    $output

}

function Get-NXZoneset {
<#
    .SYNOPSIS
        Displays Zoneset(s) configured on the Nexus switch
    .DESCRIPTION
        The function connects to the specified Nexus switch with the
        given connection object and retrieves information about the
        Zoneset(s) configured on the switch
        Cli command equivalent: show zoneset
    .PARAMETER Connection
        Connection object from the New-NXConnection function
    .PARAMETER Name
        Specify zoneset name
    .EXAMPLE
        Get-NXZoneset -Connection $connection
        This will connect to the switch with the session information stored
        in the connection object and display all zones
    .NOTES
        NAME: Get-NXZoneset
        AUTHOR: Rudi Martinsen
        CREATED: 24/04-2017
        VERSION: 0.1.0
        REVISED: 
#>
[CmdLetBinding(DefaultParameterSetName="All")]
    param(
        $Connection,
        $Name
    )

    $Resource = "zoneset"

    if($Name){
        $Resource += " name " + $Name
    }

    $zonesets = Invoke-NXApiRequest -NXConnection $Connection -Method SHOW -Resource $Resource

    $zonesetObjects = @()
    $i = 0
    $lines = $zonesets -split('[\r\n]')

    $zonesetTbl = @{}

    foreach($line in $lines){
        $i++
        if($line -like "zoneset name*"){
            $zonesetTbl.Add($line.replace("zoneset name ",""),$i)
        }
    }

    $zonesetTbl = $zonesetTbl.GetEnumerator() | Sort-Object value
    
    for($r=0;$r -lt $zonesetTbl.Count;$r++){
        $split = $zonesetTbl[$r].Name -csplit 'vsan'
        $name = $split[0]
        $vsanid = $split[($split.Length)-1].trim()

        $l = $zonesetTbl[$r].value
        
        if($r -eq $zonesetTbl.Count - 1){
            $end = $lines.Length
        }
        else{
            $end = $zonesetTbl[$r + 1].value
        }

        $zones = @()

        for($y = $l;$y -le $end - 1;$y++){
            if($lines[$y] -like "*zone name*"){
                $zone = ($lines[$y] -csplit "vsan")[0].Replace("zone name","").Trim()
                $zones += $zone
            }
        }

        $zonesetObj = New-Object PSCustomObject
        $zonesetObj | Add-Member -MemberType NoteProperty -Name Name -Value $name
        $zonesetObj | Add-Member -MemberType NoteProperty -Name VsanId -Value $vsanid
        $zonesetObj | Add-Member -MemberType NoteProperty -Name Zones -Value $zones
        $zonesetObjects += $zonesetObj

    }

    $zonesetObjects

}
