$localPackages = Join-Path $PSScriptRoot ".python_packages"
$sourcePackages = "C:\Users\kofi4\OneDrive\Documents\Vuln_App\.python_packages"

if (Test-Path (Join-Path $localPackages "typing_extensions.py")) {
    $env:PYTHONPATH = $localPackages
} elseif (Test-Path (Join-Path $sourcePackages "typing_extensions.py")) {
    $env:PYTHONPATH = $sourcePackages
} else {
    $env:PYTHONPATH = $localPackages
}

python -m uvicorn app.main:app --reload
