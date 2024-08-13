<#
.SYNOPSIS
    Checks a domain environment for the PKfail UEFI vulnerability identified by Binarly REsearch.
.DESCRIPTION
    This script checks an Active Directory domain environment for the PKfail UEFI vulnerability.  It specifically looks for an exposed UEFI test Platform Key (PK) key that was deployed to a large swatch of production systems.  For AD environments that have PowerShell remoting constrained language mode, it alternatively uses an ASCII hash table lookup to properly decode and the search the PK.
.PARAMETER OUName
    Optionally specifices a target organizational unit (OU) of interest
.PARAMETER Migrated
    Switch to use if computer objects have migrated to a different domain
.PARAMETER SearchBase
    The distinguised name path to use for computer object searching
.PARAMETER Server
    The server to use for the target domain
.EXAMPLE
    .\Check-UEFIpk.ps1

    Run with no arguments if the environment is a single domain.
.EXAMPLE
    .\Check-UEFIpk.ps1 | Sort-Object CsModel | Format-Table -AutoSize 

    Same as the first example but with a table format and a cleaner output.  Make sure to have the viewable console area wide enough or the output may be truncated.
.EXAMPLE
    .\Check-UEFIpk.ps1 -OUName Manila

    Run with the OUName parameter to specific a target OU of interest.
.EXAMPLE
    .\Check-UEFIpk.ps1 -OUName Manila -Migrated -SearchBase 'ou=computer,ou=location,dc=company,dc=org' -Server 'company.org'

    Run with the OUName parameter and the Migrated switch to specific a target OU location of interest.  You must also specify the SearchBase and Server to use for the query.
.NOTES
    Version 0.03
    Authors:
        Sam Pursglove
        Binarly REsearch - https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem
    Last modified: 02 August 2024
#>

[CmdletBinding(DefaultParameterSetName='Domain')]
param (
    [Parameter(ParameterSetName='Domain', Mandatory=$False, Position=0, HelpMessage='Target OU name')]
    [Parameter(ParameterSetName='Migrated', Mandatory=$True, Position=0, HelpMessage='Target OU name')]
    [string]$OUName = '',

    [Parameter(ParameterSetName='Migrated', Mandatory=$True, HelpMessage='Switch to change the search type for AD migrated systems')]
    [Switch]$Migrated,

    [Parameter(ParameterSetName='Migrated', Mandatory=$True, HelpMessage='The distinguished name path')]
    [string]$SearchBase = '',

    [Parameter(ParameterSetName='Migrated', Mandatory=$True, HelpMessage='Domain controller server')]
    [string]$Server = ''
)

# build parameter options for splatting depending on the desired search environment
if ($migrated) {

    $computersArgs = @{
        Filter = "(msExchExtensionCustomAttribute1 -like '*$($OUName)*') -and (OperatingSystem -like 'Windows*')"
        Properties = 'OperatingSystem','msExchExtensionCustomAttribute1'
        SearchBase = $SearchBase
        Server = $Server
    }
} elseif($OUName) {

    $computersArgs = @{
        Filter = "OperatingSystem -like 'Windows*'"
        Properties = 'OperatingSystem'
        SearchBase = 'OU=' + $OUName + ',' + (Get-ADDomain).DistinguishedName
    }
} else {

    $computersArgs = @{
        Filter = "OperatingSystem -like 'Windows*'"
        Properties = 'OperatingSystem'
        SearchBase = (Get-ADDomain).DistinguishedName
    }
}


$computers = Get-ADComputer @computersArgs

# get target systems from AD
$sessionOpt = New-PSSessionOption -NoMachineProfile 
New-PSSession -ComputerName $computers.Name -SessionOption $sessionOpt -ErrorAction SilentlyContinue | Out-Null


Invoke-Command -Session (Get-PSSession) -ScriptBlock {
    
    # function to ASCII decode the PK where PowerShell constrained language mode doesn't allow the usage of [System.Text.Encoding]::ASCII.GetString()
    function asciiNonConstrained {
        $strBuilder = @()
        $ascii = @{ 0=' ';   9="`t"; 10="`n"; 32=' ';  33='!';  34='"'; 
                   35='#';  36='$';  37='%';  38='&';  39=''''; 40='('; 
                   41=')';  42='*';  43='+';  44=',';  45='-';  46='.'; 
                   47='/';  48='0';  49='1';  50='2';  51='3';  52='4'; 
                   53='5';  54='6';  55='7';  56='8';  57='9';  58=':'; 
                   59=';';  60='<';  61='=';  62='>';  63='?';  64='@'; 
                   65='A';  66='B';  67='C';  68='D';  69='E';  70='F'; 
                   71='G';  72='H';  73='I';  74='J';  75='K';  76='L';
                   77='M';  78='N';  79='O';  80='P';  81='Q';  82='R'; 
                   83='S';  84='T';  85='U';  86='V';  87='W';  88='X';
                   89='Y';  90='Z';  91='[';  92='\';  93=']';  94='^';
                   95='_';  96='`';  97='a';  98='b';  99='c'; 100='d';
                  101='e'; 102='f'; 103='g'; 104='h'; 105='i'; 106='j';
                  107='k'; 108='l'; 109='m'; 110='n'; 111='o'; 112='p';
                  113='q'; 114='r'; 115='s'; 116='t'; 117='u'; 118='v';
                  119='w'; 120='x'; 121='y'; 122='z'; 123='{'; 124='|'; 
                  125='}'; 126='~'
                 }

        $compInfo = Get-ComputerInfo

        # perform byte-to-ASCII lookup
        if($compInfo.BiosFirmwareType -like "Uefi") {
            (Get-SecureBootUEFI PK).bytes | 
                ForEach-Object {
                    if ($ascii.ContainsKey([int]$_)) {
                        $strBuilder += $ascii[[int]$_]
                    } else {
                        $strBuilder += '?'
                    }
                }

            # join all the converted ASCII characters into a single string
            $joined = $strBuilder -join ''

            # search the string for the vulnerable PKs, the 'f' indicates it used the ASCII lookup table for data conversion
            if ($joined -match "DO NOT TRUST|DO NOT SHIP") {
                $Vulnerable = 'True (f)'
            } else {
                $Vulnerable = 'False (f)'
            }

            $compInfo | 
                Select-Object CsModel,BiosManufacturer,BiosFirmwareType,BiosName,@{Name='Vulnerable'; Expression={"$Vulnerable"}}
        } else {
            $compInfo | 
                Select-Object CsModel,BiosManufacturer,BiosFirmwareType,BiosName,@{Name='Vulnerable'; Expression={''}}
        }
    }

    # check if the environment is using PowerShell's contrained language mode, if so, then use the local lookup table for ASCII conversion
    if($ExecutionContext.SessionState.LanguageMode -like "FullLanguage") {
        
        $compInfo = Get-ComputerInfo

        # only check a system if it has UEFI, not BIOS (avoids calls throwing errors), the 'n' indiates that the native ASCII.GetString() method was used
        if($compInfo.BiosFirmwareType -like "Uefi") {
            # One line PowerShell check written by Binarly REsearch
            if([System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI PK).bytes) -match "DO NOT TRUST|DO NOT SHIP") {
                $Vulnerable = 'True (n)'
            } else {
                $Vulnerable = 'False (n)'                
            }

            $compInfo | 
                Select-Object CsModel,BiosManufacturer,BiosFirmwareType,BiosName,@{Name='Vulnerable'; Expression={"$Vulnerable"}}
        } else {
            $compInfo | 
                Select-Object CsModel,BiosManufacturer,BiosFirmwareType,BiosName,@{Name='Vulnerable'; Expression={''}}
        }

    } else { 
        asciiNonConstrained
    }
} | Select-Object PSComputerName,CsModel,BiosManufacturer,BiosFirmwareType,BiosName,Vulnerable

Get-PSSession | Remove-PSSession
