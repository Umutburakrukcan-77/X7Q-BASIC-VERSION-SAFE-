Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$ErrorActionPreference = "Stop"

function Get-ProjectRoot {
    $scriptDir = $PSScriptRoot
    if ([string]::IsNullOrWhiteSpace($scriptDir)) {
        $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    }
    Resolve-Path (Join-Path $scriptDir "..")
}

function Get-X7qBinary {
    param([string]$ProjectRoot)

    $binary = Join-Path $ProjectRoot "target\debug\x7q-secure.exe"
    if (Test-Path $binary) {
        return $binary
    }

    $cargo = Get-Command cargo -ErrorAction SilentlyContinue
    if ($null -eq $cargo) {
        throw "cargo was not found. Install Rust first, or build x7q-secure.exe into target\debug."
    }

    Push-Location $ProjectRoot
    try {
        & cargo build -p x7q-secure
        if ($LASTEXITCODE -ne 0) {
            throw "cargo build failed."
        }
    }
    finally {
        Pop-Location
    }

    if (!(Test-Path $binary)) {
        throw "x7q-secure.exe was not created: $binary"
    }
    return $binary
}

function Get-DefaultOutputPath {
    param(
        [string]$InputPath,
        [System.Windows.Forms.ComboBox]$Mode
    )

    if ([string]::IsNullOrWhiteSpace($InputPath)) {
        return ""
    }

    $directory = Split-Path -Parent $InputPath
    $root = [System.IO.Path]::GetPathRoot($InputPath)
    if ($directory.TrimEnd('\') -eq $root.TrimEnd('\')) {
        $tmp = Join-Path $root "tmp"
        $directory = $tmp
    }
    $name = [System.IO.Path]::GetFileNameWithoutExtension($InputPath)
    if ($Mode.SelectedItem -eq "PDF to x7q") {
        return (Join-Path $directory "$name.x7q")
    }
    return (Join-Path $directory "$name.pdf")
}

function Ensure-OutputDirectory {
    param([string]$OutputPath)

    $directory = Split-Path -Parent $OutputPath
    if ([string]::IsNullOrWhiteSpace($directory)) {
        return
    }
    if (!(Test-Path $directory)) {
        New-Item -ItemType Directory -Path $directory | Out-Null
    }
}

function Update-OutputFromInput {
    param(
        [System.Windows.Forms.TextBox]$InputBox,
        [System.Windows.Forms.TextBox]$OutputBox,
        [System.Windows.Forms.ComboBox]$Mode
    )

    $defaultOutput = Get-DefaultOutputPath -InputPath $InputBox.Text -Mode $Mode
    if (![string]::IsNullOrWhiteSpace($defaultOutput)) {
        $OutputBox.Text = $defaultOutput
    }
}

function Select-InputFile {
    param(
        [System.Windows.Forms.TextBox]$Target,
        [System.Windows.Forms.TextBox]$Output,
        [System.Windows.Forms.ComboBox]$Mode
    )

    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    if ($Mode.SelectedItem -eq "PDF to x7q") {
        $dialog.Filter = "PDF files (*.pdf)|*.pdf|All files (*.*)|*.*"
    }
    else {
        $dialog.Filter = "x7q files (*.x7q)|*.x7q|All files (*.*)|*.*"
    }

    if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $Target.Text = $dialog.FileName
        Update-OutputFromInput -InputBox $Target -OutputBox $Output -Mode $Mode
    }
}

function Select-OutputFile {
    param(
        [System.Windows.Forms.TextBox]$Target,
        [System.Windows.Forms.ComboBox]$Mode
    )

    $dialog = New-Object System.Windows.Forms.SaveFileDialog
    if ($Mode.SelectedItem -eq "PDF to x7q") {
        $dialog.Filter = "x7q files (*.x7q)|*.x7q|All files (*.*)|*.*"
        $dialog.DefaultExt = "x7q"
    }
    else {
        $dialog.Filter = "PDF files (*.pdf)|*.pdf|All files (*.*)|*.*"
        $dialog.DefaultExt = "pdf"
    }

    if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $Target.Text = $dialog.FileName
    }
}

function Run-Conversion {
    param(
        [System.Windows.Forms.ComboBox]$Mode,
        [System.Windows.Forms.TextBox]$InputBox,
        [System.Windows.Forms.TextBox]$OutputBox,
        [System.Windows.Forms.CheckBox]$UseKey,
        [System.Windows.Forms.TextBox]$KeyBox,
        [System.Windows.Forms.TextBox]$LogBox
    )

    if ([string]::IsNullOrWhiteSpace($InputBox.Text)) {
        throw "Input file was not selected."
    }
    if ([string]::IsNullOrWhiteSpace($OutputBox.Text)) {
        Update-OutputFromInput -InputBox $InputBox -OutputBox $OutputBox -Mode $Mode
    }
    if ([string]::IsNullOrWhiteSpace($OutputBox.Text)) {
        throw "Output file was not selected."
    }
    if (!(Test-Path $InputBox.Text)) {
        throw "Input file was not found: $($InputBox.Text)"
    }
    if ($UseKey.Checked -and [string]::IsNullOrEmpty($KeyBox.Text)) {
        throw "Key mode is enabled, but the key is empty."
    }
    Ensure-OutputDirectory -OutputPath $OutputBox.Text

    $projectRoot = Get-ProjectRoot
    $binary = Get-X7qBinary -ProjectRoot $projectRoot
    $command = if ($Mode.SelectedItem -eq "PDF to x7q") { "pdf-to-x7q" } else { "x7q-to-pdf" }

    $args = New-Object System.Collections.Generic.List[string]
    $args.Add($command)
    $args.Add($InputBox.Text)
    $args.Add($OutputBox.Text)
    if ($UseKey.Checked) {
        $args.Add("--key")
        $args.Add($KeyBox.Text)
    }

    $LogBox.AppendText("Command: $binary $($args -join ' ')`r`n")
    $output = & $binary @args 2>&1
    $exitCode = $LASTEXITCODE
    if ($null -ne $output) {
        $LogBox.AppendText(($output -join "`r`n") + "`r`n")
    }
    if ($exitCode -ne 0) {
        throw "Conversion failed. ExitCode=$exitCode"
    }
    if (!(Test-Path $OutputBox.Text)) {
        throw "Conversion command completed but output file was not created."
    }
    $LogBox.AppendText("Done: $($OutputBox.Text)`r`n")
}

$form = New-Object System.Windows.Forms.Form
$form.Text = "x7q Converter"
$form.Size = New-Object System.Drawing.Size(620, 390)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false

$modeLabel = New-Object System.Windows.Forms.Label
$modeLabel.Text = "Mode"
$modeLabel.Location = New-Object System.Drawing.Point(20, 22)
$modeLabel.Size = New-Object System.Drawing.Size(90, 22)
$form.Controls.Add($modeLabel)

$modeBox = New-Object System.Windows.Forms.ComboBox
$modeBox.DropDownStyle = "DropDownList"
$modeBox.Items.Add("PDF to x7q") | Out-Null
$modeBox.Items.Add("x7q to PDF") | Out-Null
$modeBox.SelectedIndex = 0
$modeBox.Location = New-Object System.Drawing.Point(120, 20)
$modeBox.Size = New-Object System.Drawing.Size(180, 24)
$form.Controls.Add($modeBox)

$inputLabel = New-Object System.Windows.Forms.Label
$inputLabel.Text = "Input"
$inputLabel.Location = New-Object System.Drawing.Point(20, 65)
$inputLabel.Size = New-Object System.Drawing.Size(90, 22)
$form.Controls.Add($inputLabel)

$inputBox = New-Object System.Windows.Forms.TextBox
$inputBox.Location = New-Object System.Drawing.Point(120, 62)
$inputBox.Size = New-Object System.Drawing.Size(360, 24)
$form.Controls.Add($inputBox)

$inputButton = New-Object System.Windows.Forms.Button
$inputButton.Text = "Browse"
$inputButton.Location = New-Object System.Drawing.Point(495, 60)
$inputButton.Size = New-Object System.Drawing.Size(80, 28)
$inputButton.Add_Click({ Select-InputFile -Target $inputBox -Output $outputBox -Mode $modeBox })
$form.Controls.Add($inputButton)

$outputLabel = New-Object System.Windows.Forms.Label
$outputLabel.Text = "Output"
$outputLabel.Location = New-Object System.Drawing.Point(20, 107)
$outputLabel.Size = New-Object System.Drawing.Size(90, 22)
$form.Controls.Add($outputLabel)

$outputBox = New-Object System.Windows.Forms.TextBox
$outputBox.Location = New-Object System.Drawing.Point(120, 104)
$outputBox.Size = New-Object System.Drawing.Size(360, 24)
$form.Controls.Add($outputBox)

$outputButton = New-Object System.Windows.Forms.Button
$outputButton.Text = "Browse"
$outputButton.Location = New-Object System.Drawing.Point(495, 102)
$outputButton.Size = New-Object System.Drawing.Size(80, 28)
$outputButton.Add_Click({ Select-OutputFile -Target $outputBox -Mode $modeBox })
$form.Controls.Add($outputButton)

$useKeyBox = New-Object System.Windows.Forms.CheckBox
$useKeyBox.Text = "Use key"
$useKeyBox.Location = New-Object System.Drawing.Point(120, 145)
$useKeyBox.Size = New-Object System.Drawing.Size(130, 24)
$form.Controls.Add($useKeyBox)

$keyBox = New-Object System.Windows.Forms.TextBox
$keyBox.Location = New-Object System.Drawing.Point(255, 145)
$keyBox.Size = New-Object System.Drawing.Size(225, 24)
$keyBox.UseSystemPasswordChar = $true
$form.Controls.Add($keyBox)

$runButton = New-Object System.Windows.Forms.Button
$runButton.Text = "Convert"
$runButton.Location = New-Object System.Drawing.Point(495, 142)
$runButton.Size = New-Object System.Drawing.Size(80, 30)
$form.Controls.Add($runButton)

$logBox = New-Object System.Windows.Forms.TextBox
$logBox.Location = New-Object System.Drawing.Point(20, 195)
$logBox.Size = New-Object System.Drawing.Size(555, 120)
$logBox.Multiline = $true
$logBox.ScrollBars = "Vertical"
$logBox.ReadOnly = $true
$form.Controls.Add($logBox)

$hintLabel = New-Object System.Windows.Forms.Label
$hintLabel.Text = "Note: Root-drive inputs use C:\tmp output by default. Key mode encrypts or decrypts x7q."
$hintLabel.Location = New-Object System.Drawing.Point(20, 325)
$hintLabel.Size = New-Object System.Drawing.Size(555, 22)
$form.Controls.Add($hintLabel)

$runButton.Add_Click({
    try {
        Run-Conversion -Mode $modeBox -InputBox $inputBox -OutputBox $outputBox -UseKey $useKeyBox -KeyBox $keyBox -LogBox $logBox
        [System.Windows.Forms.MessageBox]::Show("Conversion completed.", "x7q", "OK", "Information") | Out-Null
    }
    catch {
        $logBox.AppendText("Error: $($_.Exception.Message)`r`n")
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "x7q error", "OK", "Error") | Out-Null
    }
})

$modeBox.Add_SelectedIndexChanged({
    Update-OutputFromInput -InputBox $inputBox -OutputBox $outputBox -Mode $modeBox
})

[void]$form.ShowDialog()
