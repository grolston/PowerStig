#Based on code from http://www.entelechyit.com/2017/01/29/powershell-and-disa-stigs-part-3/
function Get-RegistryHive {
    [CmdletBinding()]
    param(
        [string]$InputLine,
        [string]$RuleId )
    
    $Hive = switch -regex ($strLine) {
        "HKEY_LOCAL_MACHINE" { "HKLM:" }
        "HKEY_CURRENT_USER" { "HKCU:" }
        default { $null }
    }
    
    If ($Hive) {
        Write-Debug "The identified registry hive for $RuleId : $Hive"
    } Else {
        Write-Debug "No identified registry hive for $Ruleid."
    }

    $Hive
} # close Get-RegistryHive

function Get-RegistryPath {
    [CmdletBinding()]
    param(
        [string]$InputLine,
        [string]$Rule )

    $RegPath = switch -wildcard ($strLine) {
        "Registry Path: *" { $( ($PSItem -replace "Registry Path: ", "").Trim() ) }
        default { $null }
    }
    
    If ($Path) {
        Write-Debug "The identified registry path for $Rule : $Path"
    } Else {
        Write-Debug "No identified registry path for $Rule."
    }

    $RegPath
} # close Get-RegistryPath

function Get-RegistryValueName {
    [CmdletBinding()]
    param(
        [string]$InputLine,
        [string]$Rule )
        
        $ValueName = switch -wildcard ($strLine) {
            "Value Name: *" { $( ($PSItem -replace "Value Name: ", "").Trim() ) }
            default { $null }
        }

        If ($ValueName) {
            Write-Debug "The identified value name for $Rule : $ValueName"
        } Else {
            Write-Debug "No identified value name for $Rule." 
        }

        $ValueName
} # close Get-RegistryValueName

  
function Get-RegTypeValue {
    PARAM([string]$Type)
    [string]$ValueType = switch -wildcard ($Type) { 
        "*REG_DWORD*" {"Dword"} 
        "*REG_SZ" {"String"}
        "*REG_BINARY" {"Binary"}
        "*REG_QWORD" {"Qword"}
        "*REG_MULTI_SZ" {"MultiString"}
        "*REG_EXPAND_SZ" {"ExpandString"}
    }
    write-output $ValueType
}# close Get-RegTypeValue

function New-DisaStigConfig {
    <#
  .Synopsis
    Creates a PowerShell DSC config script from
    the windows Xccdf file
  .DESCRIPTION
    Convert an windows xccdf file into a PowerShell
    DSC configuration script that utilized DSC's registry
    resourcce to set the registry values stated in the
    STIG'a check check-content XML element.
  .NOTES
    Download and unzip your benchmark from DISA from
    http://iase.disa.mil/stigs/compilations/Pages/index.aspx
    and download the cci list from the following
    http://iase.disa.mil/stigs/cci/Pages/index.aspx
  .EXAMPLE
    New-DisaStigConfig -xccdf '
      ~\Documents\U_Windows_2012_and_2012_R2_MS_STIG_V2R6_Manual-xccdf.xml' `
      -outFile ~\Desktop\WindowsDscStigConfig.ps1
  #>
    [CmdletBinding()]
    PARAM(
        # _Manual-xccdf.xml file path
        [Parameter(Mandatory = $true,
            Position = 0)]
        [ValidateScript( {Test-Path $_ })]
        [string]
        $xccdf,
        # File path to save the STIG DSC Config file
        [Parameter(Mandatory = $false,
            Position = 1)]
        [string]
        $outFile
    )
    BEGIN {
        # Load the content as XML
        try { 
            [xml]$Stigx = Get-Content -Path $xccdf -EA Stop
        }
        catch {
            write-warning "Failure converting XML for the XCCDF file."
            Write-Error $_ -ErrorAction Stop
        }
    }# close BEGIN
    #region Process Registry Fixes
    PROCESS {
        ## Exclude rules that either don't parse or are not enforcable by GPO
        $Exceptions = @('SV-87869r1_rule','SV-87871r1_rule','SV-87873r1_rule','SV-87875r2_rule','SV-87885r1_rule','SV-87889r1_rule','SV-87891r1_rule','SV-87893r1_rule'`
                        ,'SV-87895r1_rule','SV-87897r1_rule','SV-87899r1_rule','SV-87911r1_rule','SV-87917r1_rule','SV-87921r1_rule','SV-87923r1_rule','SV-87925r1_rule',`
                        'SV-87927r1_rule')
        $DscConfigCollection = @()
        ## loop through the xccdf benchmark collecting data into an object collection
        foreach ($rule in $StigX.Benchmark.Group.Rule) {
            ## create a new PSObject collecting and stripping out as required.
            $STIG = New-Object -TypeName PSObject -Property ([ordered]@{
                    RuleID               = $rule.id
                    RuleTitle            = $rule.title 
                    Severity             = $rule.severity
                    VulnerabilityDetails = $($($($rule.description) -split '</VulnDiscussion>')[0] -replace '<VulnDiscussion>', '')
                    Check                = $rule.check.'check-content'
                    Fix                  = $rule.fixtext.'#text'
                    ControlIdentifier    = $rule.ident.'#text'
                })
            ## A majority of the simple registry checks start with the Registry Hive string
            ## which we use to create our registry resource in the DSC configuration script
            ## TODO: split the logic out into a separate function
            ## TODO: Support non-registry fix content
            if (($STIG.Check -LIKE "*If the following registry value does not exist or is not configured as specified, this is a finding*") -AND ($STIG.RuleID -notin $Exceptions)) {
                $Lines = $($STIG.Check).Split("`n")
                ## loop through each line of the the CheckContent
                foreach ($line in $Lines) {
                    ## eliminate any leading or trailing spaces
                    [string]$strLine = $line.Trim()
                    ## find the registry hive
                    
                    If ($Hive -eq $Null) {
                        $Hive = Get-RegistryHive -InputLine $strLine -Rule $($STIG.Ruleid)
                    }
                    
                    ## find the registry path
                    If ($Path -eq $Null) {
                        $Path = Get-RegistryPath -InputLine $strLine -Rule $($STIG.Ruleid)
                    }

                    # Build Key
                    If ( $Key -eq $Null ) {
                        If ( ($Hive) -and ($Path) ) {
                            $Key = $Hive + $Path
                            Write-Debug "The identified key for $($STIG.Ruleid) : $Key"
                        } Else {
                            Write-Debug "No identified key for $($STIG.Ruleid)."
                        }
                    }

                    If ($ValueName -eq $Null) {
                        $ValueName = Get-RegistryValueName -InputLine $strLine -Rule $($STIG.Ruleid)
                    }

                    ## find the -ValueType portion of our audit
                    elseif ($strLine -LIKE "*Type: *") {
                        $ValueTypeParse = $($strLine -replace "Type: ", "") -replace "Value ", ""
                        $ValueType = Get-RegTypeValue $ValueTypeParse.Trim()
                        Write-Debug "The identified value type for $($STIG.Ruleid) : $ValueType"  
                    }
                    ## find the -ValueData  portion of our audit
                    elseif ($strLine -LIKE "Value: *") {
                        $ValueData = ($strLine -replace "Value: ", "" -replace "\(or less\)" -replace "\(or greater\)" -replace "\(Enabled\)").Trim()
                        ## todo: replace this with regex...list has grown
                        switch ($ValueData) {
                            '0x000000ff (255)' {$ValueData = '255'}
                            '0x00000004 (4)' {$ValueData = '4'}
                            '0x0000000f (15)' {$ValueData = '15'}
                            '0x0000000a (10)' {$ValueData = '10'}
                            '(blank)' {$ValueData = ''}
                            '0x20080000 (537395200)' {$ValueData = '537395200'}
                            '0x0000ea60 (60000)' {$ValueData = '60000'}
                            '0x20080000 (537395200)' {$ValueData = '53739520'}
                            '0x00008000 (32768) (or greater)' {$ValueData = '32768'}
                            '0x00030000 (196608) (or greater)' {$ValueData = '196608'}
                            '0x00008000 (32768) (or greater)' {$ValueData = '32768'}
                            '0x00000002 (2)' {$ValueData = '2'}
                            '0x00000384 (900)' {$ValueData = '900'}
                            '0x00000032 (50)' {$ValueData = '50'}
                            "0x00000064 (100)" {$ValueData = '100'}
                            "0x00008000 (32768)" {$ValueData = '32768'}
                            "0x00030000 (196608)" {$ValueData = '196608'}
                            "0x00008000 (32768)" {$ValueData = '32768'}
                            Default {}
                        }# close switch
                        Write-Debug "The identified value data for $($STIG.Ruleid) : $ValueData"   
                    } #close else-if chain
                }# close foreach line in lines
            ## remove any escaping characters for the comments and description...not important to maintain
            $RuleHeader = "$($STIG.RuleID) : $($STIG.Severity) (Registry)"
            $VulnsDetailsSanitized = $STIG.VulnerabilityDetails | Sanitize-String

            ## create the DSC configuration based off the parsing of the CheckContent
            $NewDscConfig = New-DSCRegistryConfig -RuleHeader $RuleHeader -RuleTitle $($STIG.RuleTitle) `
                -Description $VulnsDetailsSanitized -RuleID $($STIG.RuleID) -ValueName $ValueName -ValueData $ValueData `
                -Key $Key -ValueType $ValueType
            $DscConfigCollection += $NewDscConfig
            } elseif ($STIG.RuleID -notin $Exceptions) {
                $Lines = $($STIG.Check).Split("`n")
                $CheckLines = ""
                ## loop through each line of the the CheckContent
                foreach ($line in $Lines) {
                                            ## eliminate any leading or trailing spaces
                                            [string]$strLine = $line.Trim()
                                            $CheckLines += $strLine
                                            }#close foreach line in lines
                    $RuleHeader = "$($STIG.RuleID) : $($STIG.Severity) (Policy)"
                    $VulnsDetailsSanitized = $STIG.VulnerabilityDetails | Sanitize-String
                    ## create the DSC configuration based off the parsing of the CheckContent
                    $NewDscConfig = New-DSCPolicyConfig -RuleHeader $RuleHeader -RuleTitle $($STIG.RuleTitle) `
                        -Description $VulnsDetailsSanitized -RuleID $($STIG.RuleID) -CheckLines $CheckLines -FixText $STIG.Fix
                    $DscConfigCollection += $NewDscConfig
            } #close non-registry else
        }# close foreach rule in stig
    }# close PROCESS
    #endregion Process Registry Fixes
    END {
        $DscBody = $DscConfigCollection | Out-String 
        $ComputerName = '$ComputerName'
        $DSC = @"
  ## New STIG Audit Tool Generated on $(Get-Date)
  configuration DisaStig {
    PARAM(
      [string[]]$ComputerName="localhost"
    )
    node $ComputerName {
  $DscBody
    }# close node
  }# close DisaStig
"@
        $DSC | Out-File $outFile
    }# close END
  
}# close New-DisaStigConfig
#TODO add console count of stigs processed vs reg and non-reg
Export-ModuleMember -Function New-DisaStigConfig

function New-DSCPolicyConfig {
    PARAM(
        [string]$RuleHeader,
        [string]$RuleTitle,
        [string]$Description,
        [string]$RuleID,
        [string]$CheckLines,
        [string]$FixText
    )
    $CreateDscConfig = @"
      #region $RuleHeader
      ## Title: $($STIG.RuleTitle)
      <# 
        Description: $Description
      #>
      Registry $RuleID {
        Ensure = 'Present'
        PolicyType = 'Machine'
        KeyValueName = 'PolicyPath'
        Type = 'DWord'
        Data = '0'
        CheckLines = "$CheckLines" 
        FixText = "$FixText"
        }
      #endregion $RuleHeader

"@
    Write-Output $CreateDscConfig
}# close Create-DSCPolicyConfig
    
function New-DSCRegistryConfig {
    PARAM(
        [string]$RuleHeader,
        [string]$RuleTitle,
        [string]$Description,
        [string]$RuleID,
        [string]$ValueName,
        [string]$ValueData,
        [string]$Key,
        [string]$ValueType
    )
    $ForceString = '$true'
    $CreateDscConfig = @"
      #region $RuleHeader
      ## Title: $($STIG.RuleTitle)
      <#
        Description: $Description
      #>
      Registry $RuleID {
        Ensure = "Present"
        Key = "$Key"
        Force = $ForceString
        ValueName = "$ValueName"
        ValueData = "$ValueData"
        ValueType = "$ValueType" 
        }
      #endregion $RuleHeader

"@
    Write-Output $CreateDscConfig
}# close Create-DSCRegistryConfig

function Sanitize-String {
    PARAM([Parameter(Mandatory = $true, 
            ValueFromPipeline = $true)]
        [string]$String
    )
    $Sanitized = ($String -replace "'", "" -replace '"', '').TrimEnd();
    Write-Output $Sanitized;
}# close Sanitize-String
