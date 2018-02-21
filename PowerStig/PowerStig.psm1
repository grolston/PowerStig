#Based on code from http://www.entelechyit.com/2017/01/29/powershell-and-disa-stigs-part-3/
function Get-RegistryHive {
    [CmdletBinding()]
    param(
        [string]$InputLine,
        [string]$RuleId )
    
    $Hive = switch -regex ($strLine) {
        "HKEY_LOCAL_MACHINE" { "HKLM:" ; Break }
        "HKEY_CURRENT_USER" { "HKCU:" ; Break }
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

    $RegPath = switch -wildcard ($InputLine) {
        "Registry Path: *" { $( ($PSItem -replace "Registry Path: ", "").Trim() ) ; Break }
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
        
        $ValueName = switch -wildcard ($InputLine) {
            "Value Name: *" { $( ($PSItem -replace "Value Name: ", "").Trim() ) ; Break }
            default { $null }
        }

        If ($ValueName) {
            Write-Debug "The identified value name for $Rule : $ValueName"
        } Else {
            Write-Debug "No identified value name for $Rule." 
        }

        $ValueName
} # close Get-RegistryValueName

function Get-RegistryValueType {
    [CmdletBinding()]
    param(
        [string]$InputLine,
        [string]$Rule )

        If ($InputLine -like "*Type: *") {
            $ValueType = switch -regex ($InputLine) {
                "REG_DWORD*" { "Dword" ; Break } 
                "REG_SZ" { "String" ; Break }
                "REG_BINARY" { "Binary" ; Break }
                "REG_QWORD" { "Qword" ; Break }
                "REG_MULTI_SZ" { "MultiString" ; Break }
                "REG_EXPAND_SZ" { "ExpandString" ; Break }
                default { $null }
            }
        }
        
        If ($ValueType) {
            Write-Debug "The identified value type for $Rule : $ValueType" 
        } Else {
            Write-Debug "No identified value type for $Rule."
        }

        $ValueType
} # close Get-RegistryValueType

function Get-RegistryValueData {
    [CmdletBinding()]
    param(
        [string]$InputLine,
        [string]$Rule )

        If ($InputLine -like "*Value: *") {
            #$InputLine = ($InputLine -replace "Value: ", "" -replace "\(or less\)" -replace "\(or greater\)" -replace "\(Enabled\)").Trim()
            ## todo: replace this with regex...list has grown
            $ValueData = switch -regex ($InputLine) {
                "0x\w{8}" { $( [Convert]::ToInt32($Matches[0],16) ) ; Break }
                "\d{1}" { $Matches[0] ; Break }
                Default { $null }
            } # close switch
        }
        
        # Check to see if ValueData is a valid INT - todo: also work properly with string values 
        Try { 
            $ValueData = [INT]$ValueData
        } Catch { 
            $ValueData = $Null
        } 
        
        If ($ValueData) {
            Write-Debug "The identified value type for $Rule : $ValueData"
        } Else {
           Write-Debug "No identified value type for $Rule : $ValueData"
        }

        $ValueData
} # close Get-RegistryValueData
  
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
        $outFile,
        [Parameter(Mandatory = $false,
            Position = 2)]
        [switch]
        $DisplayRules
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
        If ($DisplayRules) {
            $UnusedRules = [System.Collections.ArrayList]@()
            $RegistryRules = [System.Collections.ArrayList]@()
        }
    }# close BEGIN
    #region Process Registry Fixes
    PROCESS {
        ## Exclude rules that either don't parse or are not enforcable by GPO
        $Exceptions = @('SV-87869r1_rule','SV-87871r1_rule','SV-87873r1_rule','SV-87875r2_rule','SV-87885r1_rule','SV-87889r1_rule','SV-87891r1_rule','SV-87893r1_rule'`
                        ,'SV-87895r1_rule','SV-87897r1_rule','SV-87899r1_rule','SV-87911r1_rule','SV-87917r1_rule','SV-87921r1_rule','SV-87923r1_rule','SV-87925r1_rule',`
                        'SV-87927r1_rule')
        $DscConfigCollection = [System.Collections.ArrayList]@()
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

            # Start with clean variables
            $Hive = $Null
            $Path = $Null
            $Key = $Null
            $ValueName = $Null
            $ValueType = $Null
            $ValueData = $Null

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

                    If ($ValueType -eq $Null) {
                        $ValueType = Get-RegistryValueType -InputLine $strLine -Rule $($STIG.Ruleid)
                    }

                    If ($ValueData -eq $Null) {
                        $ValueData = Get-RegistryValueData -InputLine $strLine -Rule $($STIG.Ruleid)
                    }
 
                }# close foreach line in lines
            ## remove any escaping characters for the comments and description...not important to maintain
            $RuleHeader = "$($STIG.RuleID) : $($STIG.Severity) (Registry)"
            $VulnsDetailsSanitized = $STIG.VulnerabilityDetails | Sanitize-String
            }

            if ($STIG.RuleID -notin $Exceptions) {
                $Lines = $($STIG.Check).Split("`n")
                $CheckLines = @()
                
                ## loop through each line of the the CheckContent
                foreach ($line in $Lines) {
                    ## eliminate any leading or trailing spaces
                    [string]$strLine = $line.Trim()
                    $CheckLines += $strLine
                } #close foreach line in lines
                    
                $RuleHeader = "$($STIG.RuleID) : $($STIG.Severity) (Policy)"
                $VulnsDetailsSanitized = $STIG.VulnerabilityDetails | Sanitize-String
                    
                $ShouldAbort = Switch ( $True ) {
                    { [String]::IsNullOrEmpty($RuleHeader) } { $true }
                    { [String]::IsNullOrEmpty($($STIG.RuleTitle)) } { $true }
                    { [String]::IsNullOrEmpty($VulnsDetailsSanitized) } { $true }
                    { [String]::IsNullOrEmpty($($STIG.RuleID)) } { $true }
                    { [String]::IsNullOrEmpty($ValueName) } { $true }
                    { [String]::IsNullOrEmpty($ValueData) } { $true }
                    { [String]::IsNullOrEmpty($Key) } { $true }
                    { [String]::IsNullOrEmpty($ValueType) } { $true }
                    default { $False }
                }
                
                If ( $ShouldAbort ) {
                    Write-Verbose "$($STIG.RuleID): Something is null, not writing"
                    If ($DisplayRules) { [Void]$UnusedRules.Add($($STIG.RuleID)) }
                    Continue
                }

                    ## create the DSC configuration based off the parsing of the CheckContent
                    $NewDscRegistryConfigParameters = @{
                        RuleHeader = $RuleHeader
                        RuleTitle = $($STIG.RuleTitle)
                        Description = $VulnsDetailsSanitized
                        RuleID = $($STIG.RuleID)
                        ValueName = $ValueName
                        ValueData = $ValueData
                        Key = $Key
                        ValueType = $ValueType
                    }
                    $NewDscConfig = New-DSCRegistryConfig @NewDscRegistryConfigParameters

                    If ($DisplayRules) { [Void]$RegistryRules.Add($($STIG.RuleID)) }
                    [Void]$DscConfigCollection.Add($NewDscConfig)
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

        If ($DisplayRules) {
            Write-Host "# of Registry Rules: $($RegistryRules.Count)"
            Write-Host "# of Unused Rules: $($UnusedRules.Count)"

            Write-Host "Registry Rules: "
            $RegistryRules

            Write-Host ""

            Write-Host "Unused Rules: "
            $UnusedRules
        }   

    }# close END
}# close New-DisaStigConfig
#TODO add console count of stigs processed vs reg and non-reg
Export-ModuleMember -Function New-DisaStigConfig

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
