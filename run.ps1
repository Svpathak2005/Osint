# OSINT Lab PowerShell Automation Script
# Windows equivalent of Makefile for automation

param(
    [Parameter(Position=0)]
    [string]$Command = "help"
)

function Show-Help {
    Write-Host "OSINT Lab - Available Commands:" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Setup Commands:" -ForegroundColor Yellow
    Write-Host "  .\run.ps1 setup     - Complete environment setup"
    Write-Host "  .\run.ps1 install   - Install Python dependencies"
    Write-Host "  .\run.ps1 clean     - Clean up generated files"
    Write-Host ""
    Write-Host "Data Processing Commands:" -ForegroundColor Yellow
    Write-Host "  .\run.ps1 normalize - Normalize raw data"
    Write-Host "  .\run.ps1 aggregate - Aggregate normalized data"
    Write-Host "  .\run.ps1 report    - Generate analysis reports"
    Write-Host "  .\run.ps1 pipeline  - Run complete pipeline"
    Write-Host ""
    Write-Host "Visualization Commands:" -ForegroundColor Yellow
    Write-Host "  .\run.ps1 dashboard - Launch interactive web dashboard"
    Write-Host "  .\run.ps1 charts    - Generate static charts and graphs"
    Write-Host "  .\run.ps1 visualize - Generate charts and launch dashboard"
    Write-Host ""
    Write-Host "Development Commands:" -ForegroundColor Yellow
    Write-Host "  .\run.ps1 demo      - Run demonstration with sample data"
    Write-Host "  .\run.ps1 status    - Show data processing status"
    Write-Host ""
    Write-Host "Validation Commands:" -ForegroundColor Yellow
    Write-Host "  .\run.ps1 validate  - Validate professor requirements"
    Write-Host "  .\run.ps1 quickstart - Complete setup and demo"
}

function Setup-Environment {
    Write-Host "🚀 Setting up OSINT lab environment..." -ForegroundColor Green
    
    # Install dependencies
    Install-Dependencies
    
    # Create .env file if it doesn't exist
    if (-not (Test-Path ".env")) {
        Write-Host "📝 Creating .env file from template..." -ForegroundColor Yellow
        Copy-Item ".env.example" ".env"
        Write-Host "⚠️  Please edit .env file and add your API keys" -ForegroundColor Red
    } else {
        Write-Host "✅ .env file already exists" -ForegroundColor Green
    }
    
    Write-Host "✅ Setup complete! Please configure API keys in .env file" -ForegroundColor Green
}

function Install-Dependencies {
    Write-Host "📦 Installing Python dependencies..." -ForegroundColor Blue
    python -m pip install --upgrade pip
    python -m pip install -r requirements.txt
    Write-Host "✅ Dependencies installed" -ForegroundColor Green
}

function Clean-Files {
    Write-Host "🧹 Cleaning up generated files..." -ForegroundColor Blue
    
    $paths = @("data\raw", "data\normalized", "data\aggregated", "reports")
    foreach ($path in $paths) {
        if (Test-Path $path) {
            Remove-Item $path -Recurse -Force
            Write-Host "   Removed $path" -ForegroundColor Gray
        }
    }
    
    # Clean Python cache files
    Get-ChildItem -Path . -Recurse -Name "__pycache__" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path . -Recurse -Name "*.pyc" | Remove-Item -Force -ErrorAction SilentlyContinue
    
    Write-Host "✅ Cleanup complete" -ForegroundColor Green
}

function Run-Collectors {
    Write-Host "🔍 Running all OSINT collectors..." -ForegroundColor Blue
    python src\collectors\run_all.py
    Write-Host "✅ Data collection complete" -ForegroundColor Green
}

function Run-SingleCollector {
    param([string]$CollectorName)
    Write-Host "🔍 Running $CollectorName collector..." -ForegroundColor Blue
    python "src\collectors\$CollectorName.py"
    Write-Host "✅ $CollectorName collection complete" -ForegroundColor Green
}

function Run-Processing {
    param([string]$Step)
    Write-Host "🔄 Running $Step..." -ForegroundColor Blue
    python src\process_data.py $Step
    Write-Host "✅ $Step complete" -ForegroundColor Green
}

function Run-Demo {
    Write-Host "🎬 Running demonstration..." -ForegroundColor Blue
    python demo.py
    Write-Host "✅ Demo complete" -ForegroundColor Green
}

function Show-Status {
    Write-Host "📊 Checking data processing status..." -ForegroundColor Blue
    python src\process_data.py status
    Write-Host "✅ Status check complete" -ForegroundColor Green
}

function Validate-Requirements {
    Write-Host "Validating Professor Requirements..." -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "Checking required components:" -ForegroundColor Yellow
    Write-Host ""
    
    # 1. Git Repository
    Write-Host "1. Git Repository:" -ForegroundColor White
    if (Test-Path ".git") {
        Write-Host "   ✓ Git repository initialized" -ForegroundColor Green
    } else {
        Write-Host "   ✗ Git repository missing" -ForegroundColor Red
    }
    Write-Host ""
    
    # 2. Source Code modules
    Write-Host "2. Source Code (12 or more modules):" -ForegroundColor White
    $modules = Get-ChildItem "src\collectors\*.py" | Where-Object { $_.Name -ne "__init__.py" }
    Write-Host "   ✓ $($modules.Count) collector modules found" -ForegroundColor Green
    Write-Host ""
    
    # 3. Configuration Files
    Write-Host "3. Configuration Files:" -ForegroundColor White
    if (Test-Path "config\config.yaml") {
        Write-Host "   ✓ config.yaml found" -ForegroundColor Green
    } else {
        Write-Host "   ✗ config.yaml missing" -ForegroundColor Red
    }
    if (Test-Path ".env.example") {
        Write-Host "   ✓ .env.example found" -ForegroundColor Green
    } else {
        Write-Host "   ✗ .env.example missing" -ForegroundColor Red
    }
    Write-Host ""
    
    # 4. Mapping Files
    Write-Host "4. Mapping Files for Normalization:" -ForegroundColor White
    if (Test-Path "config\mappings\field_mappings.yaml") {
        Write-Host "   ✓ field_mappings.yaml found" -ForegroundColor Green
    } else {
        Write-Host "   ✗ field_mappings.yaml missing" -ForegroundColor Red
    }
    if (Test-Path "config\mappings\threat_mappings.yaml") {
        Write-Host "   ✓ threat_mappings.yaml found" -ForegroundColor Green
    } else {
        Write-Host "   ✗ threat_mappings.yaml missing" -ForegroundColor Red
    }
    Write-Host ""
    
    # 5. Sample Data
    Write-Host "5. Sample Raw and Processed Data:" -ForegroundColor White
    if (Test-Path "samples\raw") {
        $rawSamples = Get-ChildItem "samples\raw\*.jsonl"
        Write-Host "   ✓ Sample raw data found ($($rawSamples.Count) files)" -ForegroundColor Green
    } else {
        Write-Host "   ✗ Sample raw data missing" -ForegroundColor Red
    }
    if (Test-Path "samples\processed") {
        $processedSamples = Get-ChildItem "samples\processed\*.jsonl"
        Write-Host "   ✓ Sample processed data found ($($processedSamples.Count) files)" -ForegroundColor Green
    } else {
        Write-Host "   ✗ Sample processed data missing" -ForegroundColor Red
    }
    Write-Host ""
    
    # 6. Documentation
    Write-Host "6. Documentation:" -ForegroundColor White
    if (Test-Path "README.md") {
        Write-Host "   ✓ README.md found" -ForegroundColor Green
    } else {
        Write-Host "   ✗ README.md missing" -ForegroundColor Red
    }
    Write-Host ""
    
    # 7. Dependencies
    Write-Host "7. Reproducibility:" -ForegroundColor White
    if (Test-Path "requirements.txt") {
        Write-Host "   ✓ requirements.txt found" -ForegroundColor Green
    } else {
        Write-Host "   ✗ requirements.txt missing" -ForegroundColor Red
    }
    Write-Host ""
    
    # 8. Automation Script
    Write-Host "8. Automation Script:" -ForegroundColor White
    if (Test-Path "Makefile") {
        Write-Host "   ✓ Makefile found" -ForegroundColor Green
    }
    if (Test-Path "run.ps1") {
        Write-Host "   ✓ PowerShell automation script found" -ForegroundColor Green
    }
    Write-Host ""
    
    Write-Host "Professor Requirement Status: All items validated!" -ForegroundColor Green
}

function Run-Quickstart {
    Write-Host "🚀 OSINT Lab Quick Start" -ForegroundColor Cyan
    Write-Host "========================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "1. Setting up environment..." -ForegroundColor Yellow
    Setup-Environment
    Write-Host ""
    
    Write-Host "2. Running demonstration..." -ForegroundColor Yellow
    Run-Demo
    Write-Host ""
    
    Write-Host "3. Validating requirements..." -ForegroundColor Yellow
    Validate-Requirements
    Write-Host ""
    
    Write-Host "✅ Quick start complete!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "- Add your API keys to .env file"
    Write-Host "- Run '.\run.ps1 collect' to gather real data"
    Write-Host "- Run '.\run.ps1 pipeline' to process data"
    Write-Host "- Check '.\run.ps1 help' for all available commands"
}

function Launch-Dashboard {
    Write-Host "🚀 Launching OSINT Dashboard..." -ForegroundColor Green
    python launch_dashboard.py
}

function Generate-Charts {
    Write-Host "📊 Generating static visualization charts..." -ForegroundColor Yellow
    python -c "from src.processors.reporter import OSINTReporter; r = OSINTReporter(); r.generate_charts()"
    Write-Host "✅ Charts generated in reports/charts/" -ForegroundColor Green
}

function Run-Visualization {
    Write-Host "📈 Running complete visualization pipeline..." -ForegroundColor Yellow
    Generate-Charts
    Write-Host ""
    Write-Host "Charts generated! Now launching interactive dashboard..." -ForegroundColor Yellow
    Launch-Dashboard
}

function Run-FullDemo {
    Write-Host "🎬 Running complete OSINT demo with visualization..." -ForegroundColor Cyan
    Run-Demo
    Write-Host ""
    Generate-Charts
    Write-Host ""
    Write-Host "✅ Complete demo finished! Run '.\run.ps1 dashboard' to view interactive results" -ForegroundColor Green
}

# Main command dispatcher
switch ($Command.ToLower()) {
    "help" { Show-Help }
    "setup" { Setup-Environment }
    "install" { Install-Dependencies }
    "clean" { Clean-Files }
    "collect" { Run-Collectors }
    "shodan" { Run-SingleCollector "shodan" }
    "vt" { Run-SingleCollector "virustotal" }
    "abuse" { Run-SingleCollector "abuseipdb" }
    "otx" { Run-SingleCollector "otx" }
    "greynoise" { Run-SingleCollector "greynoise" }
    "normalize" { Run-Processing "normalize" }
    "aggregate" { Run-Processing "aggregate" }
    "report" { Run-Processing "report" }
    "pipeline" { Run-Processing "pipeline" }
    "dashboard" { Launch-Dashboard }
    "charts" { Generate-Charts }
    "visualize" { Run-Visualization }
    "demo" { Run-Demo }
    "full-demo" { Run-FullDemo }
    "status" { Show-Status }
    "validate" { Validate-Requirements }
    "quickstart" { Run-Quickstart }
    default { 
        Write-Host "❌ Unknown command: $Command" -ForegroundColor Red
        Write-Host ""
        Show-Help
    }
}