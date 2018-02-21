$ThisModule = $MyInvocation.MyCommand.Path -replace '\.Test\.ps1$'
Write-Host "ThisModule: $ThisModule"
$ThisModuleName = $ThisModule | Split-Path -Leaf
Write-Host "ThisModuleName: $ThisModuleName"
Get-Module -Name $ThisModuleName -All | Remove-Module -Force -ErrorAction Ignore
Import-Module -Name "$ThisModule.psm1" -Force -ErrorAction Stop

InModuleScope $ThisModuleName {

    Describe "Get-RegistryHive_Test" {
        It "Makes sure correct Hive is returned" {
            Get-RegistryHive -InputLine "HKLM" | Should Be "HKLM:"
            Get-RegistryHive -InputLine "HKCU" | Should Be "HKCU:"
            Get-RegistryHive -InputLine "HKEY_LOCAL_MACHINE" | Should Be "HKLM:"
            Get-RegistryHive -InputLine "HKEY_CURRENT_USER" | Should Be "HKCU:"
            Get-RegistryHive -InputLine "blah blah: HKEY_LOCAL_MACHINE blah blah" | Should Be "HKLM:"
            Get-RegistryHive -InputLine "blah blah: HKEY_CURRENT_USER blah blah" | Should Be "HKCU:"
            Get-RegistryHive -InputLine "blah * blah: HKLM\Path\PathyPath\SuperPathyPath blah\blah\blah/blah" | Should Be "HKLM:"
            Get-RegistryHive -InputLine "blah blah: blah_blah" | Should Be $null
            Get-RegistryHive -InputLine "blah * blah: HKEY_CURRENT blah/blah/blah" | Should Be $null
        }
    }

    Describe "Get-RegistryPath_Test" {
        It "Makes sure correct Path is returned" {
            Get-RegistryPath -InputLine "Registry Path: \System\CurrentControlSet\Control\Lsa\" | Should Be "\System\CurrentControlSet\Control\Lsa\"
            Get-RegistryPath -InputLine "Registry Path: \System\Space In Path\Control\Lsa\" | Should Be "\System\Space In Path\Control\Lsa\"
            Get-RegistryPath -InputLine " Registry Path: \System\Space In Path\Control\Lsa\ " | Should Be "\System\Space In Path\Control\Lsa\"
            Get-RegistryPath -InputLine "Random String: blah\blah blah: blah 1" | Should Be $null
        }
    }

    Describe "Get-RegistryValueName" {
        It "Makes sure correct ValueName is returned" {
            Get-RegistryValueName -InputLine "Value Name: SampleValueName" | Should Be "SampleValueName"
            Get-RegistryValueName -InputLine " Value Name: SampleValueName blah blah blah" | Should Be "SampleValueName"
            Get-RegistryValueName -InputLine "Random String: blah\blah blah: blah 1" | Should Be $null
        }
    }

    Describe "Get-RegistryValueType" {
        It "Makes sure correct valueType is returned" {
            Get-RegistryValueType -InputLine "Type: REG_DWORD" | Should Be "Dword"
            Get-RegistryValueType -InputLine "Type: REG_SZ" | Should Be "String"
            Get-RegistryValueType -InputLine "Type: REG_BINARY" | Should Be "Binary"
            Get-RegistryValueType -InputLine "Type: REG_QWORD" | Should Be "Qword"
            Get-RegistryValueType -InputLine "Type: REG_MULTI_SZ" | Should Be "MultiString"
            Get-RegistryValueType -InputLine "Type: REG_EXPAND_SZ" | Should Be "ExpandString"
            Get-RegistryValueType -InputLine "Random String: blah\blah blah: blah 1" | Should be $null
        }
    }

    Describe "Get-RegistryValueData" {
        It "Makes sure correct Data is returned" {
            Get-RegistryValueData -InputLine "Value: 1" | Should Be "1"
            Get-RegistryValueData -InputLine "Value: 0x00000001" | Should Be "1"
            Get-RegistryValueData -InputLine "Random String: blah\blah blah: blah 1" | Should Be $null
        }
    }

}
