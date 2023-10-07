# MSIner
## Intro
This research was conducted and timed to correspond with TheSASCon2023 https://thesascon.com
## Description
MSIner - Security tool to check MSI installer file on LPE recovery mode CVE-2023-26078 and CVE-2023-26078

<picture>
  <img alt="View MSIner" src="https://github.com/vulerols/msiner/blob/main/view.png">
</picture>

## Fuctions
1. Scan reinstall commants in MSI Installer COM tables https://learn.microsoft.com/en-us/windows/win32/msi/database-tables
2. View reintall command
3. View and scan exploitable suspicion commands CVE-2023-26078 and CVE-2023-26078
4. View install folders
5. Predicting verdict: DETECT or CLEAN

## Demo 
<picture>
  <img alt="Demo MSIner" src="https://github.com/vulerols/msiner/blob/main/msiner_demo.gif">
</picture>

## Usage
1. Download and install .NET 6.0 runtime in release https://github.com/vulerols/msiner/releases/tag/production
2. Run 
```
msiner.exe <file.msi>
```

## Code
This tool is written in C# in Visual Studio using YandexGPT
