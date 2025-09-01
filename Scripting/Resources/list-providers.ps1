param(
    [Parameter(Mandatory = $true)]
    [string]$LogPath,

    [Parameter(Mandatory = $true)]
    [string]$OutFile
)

Add-Type -AssemblyName System.Core

# Prepare the query (all events in file)
$query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($LogPath, [System.Diagnostics.Eventing.Reader.PathType]::FilePath)

# Reader object
$reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query)

# Open output stream once
$sw = [System.IO.StreamWriter]::new($OutFile, $false, [System.Text.Encoding]::UTF8)

try {
    while ($event = $reader.ReadEvent()) {
        $sw.WriteLine($event.ProviderName)
        $event.Dispose()   # release resources quickly
    }
}
finally {
    $sw.Close()
    $reader.Dispose()
}
