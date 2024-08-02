<#
.SYNOPSIS
    
.DESCRIPTION
    
.PARAMETER OUName

.PARAMETER Migrated

.PARAMETER SearchBase

.PARAMETER Server
    
.EXAMPLE

.NOTES
    Version 0.02
    Authors:
        Sam Pursglove
        Binarly REsearch
    Last modified: 02 August 2024
#>

[CmdletBinding(DefaultParameterSetName='Domain')]
param (
    [Parameter(ParameterSetName='Domain', Mandatory=$False, Position=0, HelpMessage='Target OU name')]
    [Parameter(ParameterSetName='Migrated', Mandatory=$True, Position=0, HelpMessage='Target OU name')]
    [string]$OUName = '',

    [Parameter(ParameterSetName='Migrated', Mandatory=$True, HelpMessage='Switch to change the search type for AD migrated systems')]
    [Switch]$Migrated,

    [Parameter(ParameterSetName='Migrated', Mandatory=$True, HelpMessage='Domain controller server')]
    [string]$SearchBase = '',

    [Parameter(ParameterSetName='Migrated', Mandatory=$True, HelpMessage='Domain controller server')]
    [string]$Server = ''
)

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
    
    function asciiNonConstrained {
        $out = @()
        $ascii = @{0=' '; 9="`t"; 10="`n"; 32=' '; 33='!'; 34='"'; 35='#'; 36='$'; 37='%';
                   38='&'; 39=''''; 40='('; 41=')'; 42='*'; 43='+'; 44=','; 45='-';
                   46='.'; 47='/'; 48='0'; 49='1'; 50='2'; 51='3'; 52='4'; 53='5';
                   54='6'; 55='7'; 56='8'; 57='9'; 58=':'; 59=';'; 60='<'; 61='=';
                   62='>'; 63='?'; 64='@'; 65='A'; 66='B'; 67='C'; 68='D'; 69='E';
               70='F'; 71='G'; 72='H'; 73='I'; 74='J'; 75='K'; 76='L'; 77='M';
               78='N'; 79='O'; 80='P'; 81='Q'; 82='R'; 83='S'; 84='T'; 85='U';
               86='V'; 87='W'; 88='X'; 89='Y'; 90='Z'; 91='['; 92='\'; 93=']';
               94='^'; 95='_'; 96='`'; 97='a'; 98='b'; 99='c'; 100='d'; 101='e';
               102='f'; 103='g'; 104='h'; 105='i'; 106='j'; 107='k'; 108='l';
               109='m'; 110='n'; 111='o'; 112='p'; 113='q'; 114='r'; 115='s';
               116='t'; 117='u'; 118='v'; 119='w'; 120='x'; 121='y'; 122='z';
               123='{'; 124='|'; 125='}'; 126='~'
        }

        if(Get-Command Get-SecureBootUEFI -ErrorAction SilentlyContinue) {
            (Get-SecureBootUEFI PK).bytes | 
                ForEach-Object {
                    if ($ascii.ContainsKey([int]$_)) {
                        $out += $ascii[[int]$_]
                    } else {
                        $out += '?'
                    }
                }

            $temp = $out -join ''

            if ($temp -match "DO NOT TRUST|DO NOT SHIP") {
                $Vulnerable = 'True (f)'
            } else {
                $Vulnerable = 'False (f)'
            }

            Get-ComputerInfo | 
                Select-Object CsModel,BiosManufacturer,BiosName,@{Name='Vulnerable'; Expression={"$Vulnerable"}}
        } 
    }


    if($ExecutionContext.SessionState.LanguageMode -like "FullLanguage") { 
        if(Get-Command Get-SecureBootUEFI -ErrorAction SilentlyContinue) {
            # One line PowerShell check code provided by Binarly REsearch
            if([System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI PK).bytes) -match "DO NOT TRUST|DO NOT SHIP") {
                $Vulnerable = 'True (n)'
            } else {
                $Vulnerable = 'False (n)'                
            }

            Get-ComputerInfo | 
                Select-Object CsModel,BiosManufacturer,BiosName,@{Name='Vulnerable'; Expression={"$Vulnerable"}}
        }

    } else { 
        asciiNonConstrained
    }
} | Select-Object PSComputerName,CsModel,BiosManufacturer,BiosName,Vulnerable

Get-PSSession | Remove-PSSession