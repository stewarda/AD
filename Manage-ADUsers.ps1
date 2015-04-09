#=====================================================================================================================#
# AUTHOR: Dan Stewart                                                                                                 #
# DATE:   3/24/2015                                                                                                   #
# Version:  1.0                                                                                                       #
# COMMENT: AD User Management                                                                                         #
#=====================================================================================================================#
# Creates a new AD user with basic attributes provided by HR. Creates in correct OU and adds to correct groups.       #
#=====================================================================================================================#
#=====================================================================================================================#
# Functions                                                                                                           #
#=====================================================================================================================#
<#
.SYNOPSIS
    Disables AD user
.DESCRIPTION
    Disables AD user account
.PARAMETER FirstName
    The first name of the new user. If the user has a prefered name (Mike vs Michael) please use it.
.PARAMETER LastName
    The last name of the new user.
.PARAMETER EEID
.OUTPUTS
    Returns $AllRDSInstances which is an array of PS objects containing the following information:
    AWSAccountNumber:       The AWS account number that contains the RDS instance.
    AWSAccountName:         The AWS account name that contains the RDS instance.
.NOTES
    NAME......:  Disable-ADUser
    VERSION...:  1.0
    AUTHOR....:  Dan Stewart
    CREATED...:  3/20/15
.EXAMPLE
    New-UserAccount -FirstName 'Dan' -LastName 'Stewart' -Department 'IT' -Title 'Senior Security Engineer' -AssetTag 1234
    Creates a new AD user and populates the following fields (Name, GivenName, SurName, DisplayName, SAMAccountName, UPN, Email address, Title, Description and Department)
    Adds user to department AD group
    Places user in department users OU
    Creates computer object and places in department computers OU
#>
function Disable-ADUser
{
    [CmdletBinding()]
    param ( 
        [Parameter(Mandatory=$false,HelpMessage="Enter the first name of the new user. If the user has a prefered name (Mike vs Michael) please use it.")]
        [String]
        $UserNameToDisable,

        [Parameter(Mandatory=$false,HelpMessage="Enter the first name of the new user. If the user has a prefered name (Mike vs Michael) please use it.")]
        [String]
        $EEID,

        [Parameter(Mandatory=$false,HelpMessage="Enter the first name of the new user. If the user has a prefered name (Mike vs Michael) please use it.")]
        [String]
        $Email,

        [Parameter(Mandatory=$true,HelpMessage="Enter the first name of the new user. If the user has a prefered name (Mike vs Michael) please use it.")]
        [String]
        $DisabledGroup,

        [Parameter(Mandatory=$true,HelpMessage="Enter the first name of the new user. If the user has a prefered name (Mike vs Michael) please use it.")]
        [String]
        $DisabledOU,

        [Parameter(Mandatory=$true,HelpMessage="Enter the first name of the new user. If the user has a prefered name (Mike vs Michael) please use it.")]
        [Int]
        $DaysToDelete
    )

    $MemberOf = @()
    
    # Check whether the user exists
    $UsertoDisable = Get-ADUser -Filter * -Properties * | where {$_.samAccountName -eq $UserNameToDisable -or $_.mail -eq $Email -or $_.employeeID -eq $EEID }

    if ($UsertoDisable) 
    {
        write-verbose "Found useraccount to disable"
    }

    else
    {
        $Host.UI.WriteErrorLine("`nUnable to find user account.`nUser: $UserNameToDisable") 
        Return 
    }

    $DisableGroupObj = Get-ADGroup -Identity $DisabledGroup -Properties primarygrouptoken

    $Description = "To Be Deleted On: " + "$((get-date).adddays($DaysToDelete).toshortdatestring())"

    # Disable account, update description     
    Set-ADuser -Identity $UsertoDisable -Description $Description -passthru | Disable-ADAccount

    # Update primary group
    if ($($UsertoDisable.PrimaryGroup) -ne $($DisableGroupObj.primarygrouptoken) )
    {
        Add-ADGroupMember -Identity $($DisableGroupObj.SamAccountName) -Members $($UsertoDisable.samAccountName)
        Set-ADObject -Identity $UsertoDisable -Replace @{primaryGroupID=$($DisableGroupObj.primarygrouptoken)}
    }

    $MemberOfGroups = Get-ADPrincipalGroupMembership -Identity $($UsertoDisable.samAccountName)
    
    foreach ($Group in $MemberOfGroups)
    {
        if ($($Group.SamAccountName) -ne $DisabledGroup)
        {
            Remove-ADGroupMember -Identity $($Group.SamAccountName) -Members $($UsertoDisable.SAMAccountName) -Confirm:$false
            write-verbose "Removed from: $($Group.SamAccountName)"
            $MemberOf += $($Group.SamAccountName)
        }
    }

    Move-ADObject -Identity $UsertoDisable -TargetPath $DisabledOU

    $DisabledUserInfo = [ordered]  @{
                    FirstName="$($UsertoDisable.GivenName)";
                    LastName="$($UsertoDisable.SurName)";
                    Title="$($UsertoDisable.Title)";
                    Supervisor="$($UsertoDisable.Manager)";
                    Department="$($UsertoDisable.Department)";
                    sAMAccountName="$($UsertoDisable.SamAccountName)";
                    EmailAddress="$($UsertoDisable.mail)";
                    MemberOf="$($MemberOf -join ",")"
                }
    
    $DisabledUserObj = New-Object -Type PSObject -Prop $DisabledUserInfo
    $DisabledUserObj
}
<#
.SYNOPSIS
    Gets the default domain password policy
.DESCRIPTION
    Gets the default domain password policy and returns information about length and complexity requirements.
.OUTPUTS
    Returns $PasswordPolicyObj which is an array of PS objects containing the following information:
    DomainNam:                  The name of the domain that the password policy is being checked for.
    MinPasswordLength:          The minimum length requirement for an account password.
    MinPasswordAge:             The minimum age for a password, before it can be reset.
    MaxPasswordAge:             The maxium number of days before a password must be reset.
    RequireUpperCase:           The password must contain an upper case charecter (True/False).
    RequireLowerCase:           The password must contain an upper case charecter (True/False).
    RequireNumber:              The password must contain a number (True/False).
    RequireSpecialCharecter:    The password must contain a special chatecter (True/False).
    PasswordHistory:            The number of previous passwords that can not be reused.
.NOTES
    NAME......:  Get-ADDomainPasswordRequirements
    VERSION...:  1.0
    AUTHOR....:  Dan Stewart
    CREATED...:  4/6/15
.EXAMPLE
    Get-ADDomainPasswordRequirements
    Gets 
#>
function Get-ADDomainPasswordRequirements
{
    try
    {
        $ADPasswordPolicyInfo = [ordered] @{
                                DomainName="$($(Get-ADDomain).DNSRoot)";
                                MinPasswordLength="$($(Get-ADDefaultDomainPasswordPolicy).MinPasswordLength)";
                                MinPasswordAge="$($(Get-ADDefaultDomainPasswordPolicy).MinPasswordAge)";
                                MaxPasswordAge="$($(Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge)";  
                                RequireUpperCase="$($(Get-ADDefaultDomainPasswordPolicy).ComplexityEnabled)";
                                RequireLowerCase="$($(Get-ADDefaultDomainPasswordPolicy).ComplexityEnabled)";
                                RequireNumber="$($(Get-ADDefaultDomainPasswordPolicy).ComplexityEnabled)";
                                RequireSpecialCharecter="$($(Get-ADDefaultDomainPasswordPolicy).ComplexityEnabled)";
                                PasswordHistory="$($(Get-ADDefaultDomainPasswordPolicy).PasswordHistoryCount)"
                            }

        $PasswordPolicyObj = New-Object -Type PSObject -Prop $ADPasswordPolicyInfo
        $PasswordPolicyObj
    }

    Catch
    {
        $Host.UI.WriteErrorLine("`nUnable to retrive domain password policy.`nError: $_.error`n")
    }
}
<#
.Synopsis
    Creates a complex, random password
.DESCRIPTION
    Returns a complex, random password based on input paramaters to define length and complexity.
.PARAMETER Length 
    The length of the new password being created (number of characters total). (default value is 12).
.PARAMETER IncludeLowercaseLetters
    Include lowercase letters in the new password being created. (default value is true)
.PARAMETER IncludeUppercaseLetters 
    Include uppercase letters in the new password being created. (default value is true)
.PARAMETER IncludeNumbers
    Include numbers in the new password being created. (default value is true)
.PARAMETER IncludeSpecialChars
    Include special charecters (= + _ ? ! - # * & @ % ) in the new password being created.
.PARAMETER NoSimilarCharacters
    Remove similar charecters (i, l, o, 1, 0, I) in new password being created? (default value is true)
.OUTPUTS
    Returns $Password which is a string containing the new random,complex password.
.EXAMPLE
    New-RandomComplexPassword -Length 10
    Creates a new random, complex password that is 10 characters long using the pre-defined defaults (include lowercase, uppercase, numbers, special characters and no similar characters)
.NOTES
    Script based on: http://blog.morg.nl/2014/01/generate-a-random-strong-password-in-powershell/
    (c) Morgan de Jonge CC BY SA
#>
function New-RandomComplexPassword
{
    [CmdletBinding()]
    Param (

    [Parameter(Mandatory=$false,HelpMessage="Enter length (number of charecters) of the new password being created (default value is 12 and minimum length is 10).")]
    [ValidateNotNullOrEmpty()]
    [int]
    $Length = '12',

    [Parameter(Mandatory=$false,HelpMessage="Use lower-case charecters in new password? (default value is true).")]
    [ValidateNotNullOrEmpty()]    
    [bool] 
    $IncludeLowercaseLetters = $true,

    [Parameter(Mandatory=$false,HelpMessage="Use upper-case charecters in new password? (default value is true).")]
    [ValidateNotNullOrEmpty()]    
    [bool] 
    $IncludeUppercaseLetters = $true,

    [Parameter(Mandatory=$false,HelpMessage="Use numbers in new password? (default value is true).")]
    [ValidateNotNullOrEmpty()]    
    [bool] 
    $IncludeNumbers = $true,

    [Parameter(Mandatory=$false,HelpMessage="Use special charecters (= + _ ? ! - # * & @ % ) in new password? (default value is true).")]
    [ValidateNotNullOrEmpty()]    
    [bool] 
    $IncludeSpecialChars = $true,

    [Parameter(Mandatory=$false,HelpMessage="Remove similar charecters (i, l, o, 1, 0, I) in new password? (default value is true).")]
    [ValidateNotNullOrEmpty()]    
    [bool] 
    $NoSimilarCharacters  = $true
    )
 
    # Validate params
    if($length -lt 10) 
    {
        $exception = New-Object Exception "The minimum password length is 10"
        Throw $exception
    }

    if ($includeLowercaseLetters -eq $false -and 
            $includeUppercaseLetters -eq $false -and
            $includeNumbers -eq $false -and
            $includeSpecialChars -eq $false) 
    {
        $exception = New-Object Exception "At least one set of included characters must be specified"
        Throw $exception
    }
 
    #Available characters
    $CharsToSkip = [char]"i", [char]"l", [char]"o", [char]"1", [char]"0", [char]"I"
    $AvailableCharsForPassword = $null;
    $uppercaseChars = $null 
    for($a = 65; $a -le 90; $a++) { if($noSimilarCharacters -eq $false -or [char][byte]$a -notin $CharsToSkip) {$uppercaseChars += ,[char][byte]$a }}
    $lowercaseChars = $null
    for($a = 97; $a -le 122; $a++) { if($noSimilarCharacters -eq $false -or [char][byte]$a -notin $CharsToSkip) {$lowercaseChars += ,[char][byte]$a }}
    $digitChars = $null
    for($a = 48; $a -le 57; $a++) { if($noSimilarCharacters -eq $false -or [char][byte]$a -notin $CharsToSkip) {$digitChars += ,[char][byte]$a }}
    $specialChars = $null
    $specialChars += [char]"=", [char]"+", [char]"_", [char]"?", [char]"!", [char]"-", [char]"#", [char]"$", [char]"*", [char]"&", [char]"@", [char]"%"
 
    $TemplateLetters = $null
    if($includeLowercaseLetters) 
    { 
        $TemplateLetters += "L" 
    }

    if($includeUppercaseLetters) 
    { 
        $TemplateLetters += "U" 
    }

    if($includeNumbers) 
    { 
        $TemplateLetters += "N" 
    }

    if($includeSpecialChars) 
    { 
        $TemplateLetters += "S" 
    }

    $PasswordTemplate = @()
    
    # Set password template, to ensure that required chars are included
    do {   
        $PasswordTemplate.Clear()
        for($loop = 1; $loop -le $length; $loop++) {
            $PasswordTemplate += $TemplateLetters.Substring((Get-Random -Maximum $TemplateLetters.Length),1)
        }
    }
    while ((
        (($includeLowercaseLetters -eq $false) -or ($PasswordTemplate -contains "L")) -and
        (($includeUppercaseLetters -eq $false) -or ($PasswordTemplate -contains "U")) -and
        (($includeNumbers -eq $false) -or ($PasswordTemplate -contains "N")) -and
        (($includeSpecialChars -eq $false) -or ($PasswordTemplate -contains "S"))) -eq $false
    )
    #$PasswordTemplate now contains an array with at least one of each included character type (uppercase, lowercase, number and/or special)
 
    foreach($char in $PasswordTemplate) 
    {
        switch ($char) {
            L { $Password += $lowercaseChars | Get-Random }
            U { $Password += $uppercaseChars | Get-Random }
            N { $Password += $digitChars | Get-Random }
            S { $Password += $specialChars | Get-Random }
        }
    }
 
    return $Password
}
<#
.SYNOPSIS
    Creates a new AD user with basic attributes
.DESCRIPTION
    Creates a new AD user with basic attributes, places in correct OU and security group
.PARAMETER FirstName
    The first name of the new user. If the user has a prefered name (Mike vs Michael) please use it.
.PARAMETER LastName
    The last name of the new user.
.PARAMETER Department
    Enter the name of the new users department. It must be one of the following: Sales - Employer, Business Development, Client Services, Sales - Lead Development, Consumer Marketing, B2B Marketing, Public Relations, Data Science, Product Mgmt and Design, Jobs and Search, Executive, Finance, Human Resources, Legal, IT, Facilities, Recruiting, Engineering, Content Operations
.PARAMETER Password
    The 10 character, complex password for the new user account.
.PARAMETER Path
    The path for the OU in which to create the user account, should be the OU's DN. (default OU is _Users under the users Department OU.
.OUTPUTS
    Returns $AllRDSInstances which is an array of PS objects containing the following information:
    AWSAccountNumber:       The AWS account number that contains the RDS instance.
    AWSAccountName:         The AWS account name that contains the RDS instance.
.NOTES
    NAME......:  New-ADUserAccount
    VERSION...:  1.0
    AUTHOR....:  Dan Stewart
    CREATED...:  3/20/15
.EXAMPLE
    New-UserADAccount -FirstName 'Dan' -LastName 'Stewart' -Department 'IT' -Password '&8390hdYwl1' -Path 'OU=_USERS,OU=IT,OU=GD_USERS,DC=glassdoor,DC=ad'
    Creates a new AD user and populates the following fields (Name, GivenName, SurName, DisplayName, SAMAccountName, UPN, Email address, Title, Description and Department)
    Adds user to department AD group
    Places user in department users OU
    Creates computer object and places in department computers OU
#>
function New-ADUserAccount
{
    [CmdletBinding()]
    param ( 
        [Parameter(Mandatory=$true,HelpMessage="Enter the first name of the new user. If the user has a prefered name (Mike vs Michael) please use it.")]
        [String]
        $FirstName,

        [Parameter(Mandatory=$true,HelpMessage="Enter the last name of the new user.")]
        [String]
        $LastName,

        [Parameter(Mandatory=$true,HelpMessage="Enter the name of the new users department.")]
        [String]
        [ValidateSet("Sales - Employer", "Business Development", "Client Services", "Sales - Lead Development", "Consumer Marketing", "B2B Marketing", "Public Relations", "Data Science", "Product Mgmt and Design", "Jobs and Search", "Executive", "Finance", "Human Resources", "Legal", "IT", "Facilities", "Recruiting", "Engineering", "Content Operations")]
        $Department,

        [Parameter(Mandatory=$false,HelpMessage="Enter the 10 character, complex password for the new user account.")]
        [ValidateLength(10,128)]
        [String]
        $Password,

        [Parameter(Mandatory=$false,HelpMessage="Enter the OU path for user accounts (default OU is Users under the Department OU.")]
        [String]
        $Path,

        [Parameter(Mandatory=$false,HelpMessage="Enter the name of the domain for the new user's email (default = glassdoor.com).")]
        [String]
        $EmailDomainName='glassdoor.com'    
    ) 

    # Parse department name and replace spaces and dashes with underscores
    $DepartmentName = $($Department) -Replace(" - "," ")
    $DepartmentName = $($DepartmentName).Replace(" ","_")

    # Create computer name 
    #$Computername = $($FirstName + $LastName.Substring(0,1) + '-' + $AssetTag).ToUpper()

    # Check whether the user already exists
    if (Get-ADUser -Filter * | where {$_.samAccountName -like $($FirstName + '.' + $LastName) -or $_.mail -like $($FirstName + '.' + $LastName + '@' + $EmailDomainName) })
    {
        $Host.UI.WriteErrorLine("`nThe user account already exists, please check in AD.`nsamAccountName = $($FirstName + '.' + $LastName)`n") 
        Return 
    }

    # Validate that the users OU exists
    #if (!(Get-ADOrganizationalUnit -Filter * | where {$_.distinguishedname -like $('OU=_USERS,' + "OU=$DepartmentName," + $RootPath) } ))
    if (!(Get-ADOrganizationalUnit -Filter * | where {$_.distinguishedname -like $Path } ))
    {
        $Host.UI.WriteErrorLine("`nThe OU does not exist, please check in AD.`nOU path = $Path`n") 
        Return 
    }

    else 
    {
        write-verbose "OU does exist.OU Path = $Path"    
    }

    $FirstName = (Get-Culture).textinfo.totitlecase($FirstName.tolower())
    $LastName = (Get-Culture).textinfo.totitlecase($LastName.tolower())
    $LowerFirstName = $FirstName.tolower()
    $LowerLastName = $LastName.tolower()

    # Generate random password
    $RandomPassword = New-RandomComplexPassword

    # Create user account
    $NewUser = New-ADUser -Name $($FirstName + ' ' + $LastName) `
                           -GivenName $FirstName `
                           -SurName $LastName  `
                           -DisplayName $($FirstName + ' ' + $LastName) `
                           -SamAccountName $($LowerFirstName + '.' + $LowerLastName) `
                           -UserPrincipalName $($LowerFirstName + '.' + $LowerLastName + '@' + $((Get-ADDomain).DNSRoot)) `
                           -EmailAddress $($LowerFirstName + '.' + $LowerLastName + '@' + $EmailDomainName) `
                           -Path $Path `
                           -AccountPassword (ConvertTo-SecureString $RandomPassword -AsPlainText -force) `
                           -Enabled $True `
                           -ChangePasswordAtLogon $True `
                           -Passthru
                           #-Department $Department `

    
    $NewUserInfo = [ordered]  @{
                    FirstName="$($NewUser.GivenName)";
                    LastName="$($NewUser.SurName)";
                    #Department="$Department";
                    sAMAccountName="$($NewUser.SamAccountName)";
                    EmailAddress="$($FirstName + '.' + $LastName + '@' + $EmailDomainName)";
                    UserPath="$Path"
                    #MemberOf="$('ALL_' + $DepartmentName)"
                    Password="$RandomPassword"
                }
    
    $NewUserInfo
}
#>
<#
.SYNOPSIS
    Creates a new AD computer
.DESCRIPTION
    Checks that the paramaters are valid and then creates a new AD computer in the correct OU, assigns an owner and adds the type to the description. 
.PARAMETER UserName
    The username (samAccountName) of the owner of the new computer.
.PARAMETER AssetTag
    The asset tag of the new users laptop (must be 2-5 numbers long").
.PARAMETER LaptopType
    The type of laptop being issued for the new user (must be one of Macbook Air, Macbook Pro, Thinkpad x240,Thinkpad T540p)
.PARAMETER Path
    The path for the OU in which to create the computer account, should be the OU's DN. (default OU is _Computers under the users Department OU.
.OUTPUTS
    Returns $NewComputerInfo which is an array of PS objects containing the following information:
    Computername:       The samAccountname of the new computer object. This comprises of firstname + inital of  
                        lastname, a dash and then the asset tag number. 
    Owner:              The samAccountname of the owner of the new computer object.
    AssetTag:           The asset tag for the new computer object.
    ComputerType:       The laptop model of the new computer object.
    Path:               The DN of the OU in which the new computer object was created.
.NOTES
    NAME......:  New-ADComputerAccount
    VERSION...:  1.0
    AUTHOR....:  Dan Stewart
    CREATED...:  3/20/15
.EXAMPLE
    New-ADComputerAccount -UserName 'Bob.Smith' -AssetTag 1234 -LaptopType 'Macbook Air' -Path 'OU=_COMPUTERS,OU=IT,OU=GD_USERS,DC=glassdoor,DC=ad'
    Creates a new AD computer object with the name bobs-1234 in the IT department computers OU. Adds the computer type to the description field.
#>
function New-ADComputerAccount
{
    [CmdletBinding()]
    param ( 
        [Parameter(Mandatory=$true,HelpMessage="Enter the username (samAccountName) of the owner of the computer.")]
        [String]
        $UserName,

        [Parameter(Mandatory=$true,HelpMessage="Enter the asset tag of the new users laptop. (must be 2-5 numbers long")]
        [ValidateLength(2,5)]
        [string]
        $AssetTag,

        [Parameter(Mandatory=$false,HelpMessage="Enter the type of laptop being issued for the new user")]
        [String]
        [ValidateSet("Macbook Air", "Macbook Pro", "Thinkpad x240","Thinkpad T540p")]
        $LaptopType,

        [Parameter(Mandatory=$true,HelpMessage="Enter the path for the OU in which to create the computer account, should be the OU's DN. (default OU is _Computers under the users Department OU.")]
        [String]
        $Path      
    ) 

    # Check whether the user already exists
    $UserExist = Get-ADUser -Filter * | where {$_.samAccountName -like $UserName }

    if (!($UserExist))
    {
        $Host.UI.WriteErrorLine("`nThe user account does not exist, please check in AD.`nUserName = $UserName`n") 
        Return 
    }

    # Create computer name 
    $Computername = $($($UserExist.GivenName) + $($($UserExist.Surname).Substring(0,1)) + '-' + $AssetTag).ToUpper()

    # Check whether the computer already exists
    if (Get-ADcomputer -Filter * | where {$_.name -eq $Computername } )
    {
        $Host.UI.WriteErrorLine("`nThe computer account already exists, please check in AD.`nComputername = $Computername`n") 
        Return 
    }

    # Validate that the computers OU exists
    if (!(Get-ADOrganizationalUnit -Filter * | where {$_.distinguishedname -like $Path } ))
    {
        $Host.UI.WriteErrorLine("`nThe OU does not exist, please check in AD.`nOU path = $('OU=_COMPUTERS,' + "OU=$DepartmentName," + $RootPath)`n") 
        Return 
    }

    write-verbose "Creating Computer: $Computername in: $ComputerPath OU"
    write-verbose "Owner: $UserName AssetTag: Type: $LaptopType "

    $NewComputer = New-ADComputer -Name $Computername -SamAccountName $Computername -Path $Path -ManagedBy $UserName -Description "$LaptopType - Owner: $UserName" -passthru

    $NewComputerInfo = [ordered]  @{
                    ComputerName="$($NewComputer.Name)";
                    Owner="$UserName";
                    AssetTag="$AssetTag";
                    ComputerPath="$Path";
                    ComputerType="$LaptopType"
                }
    
    $NewComputerInfo
}
<#
.SYNOPSIS
    Reset AD user password
.DESCRIPTION
    Resets AD users password, first checking account to see if it exists. You can specify a password or create a new complex password.
.PARAMETER UserName
    The user accountname (samAccountName) in the format of first.last (e.g john.smith).
.PARAMETER NewPassword
    The new password to set for the users account, it must comply to the domain password policy. If not specified a new complex password will be created.
.PARAMETER NewSecurePassword
    The new secure password to set for the users account (as a secure string) It must comply to the domain password policy. If neither NewPassword or NewSecurePassword are specified a new complex password will be created.
.OUTPUTS
    Returns $NewPasswordObj which is an array of PS objects containing the following information:
    Username:           The username (samAccountname) of the password that the password is being reset for.
    NewPassword:        The plaintext password for the useraccount.
.NOTES
    NAME......:  Reset-ADUserPassword
    VERSION...:  1.0
    AUTHOR....:  Dan Stewart
    CREATED...:  4/7/15
.EXAMPLE
    Reset-ADUserPassword -UserName 'john.smith' -NewPassword 'P@ssword123'   
    Resets the AD account password for username john.smith to P@ssword123
.EXAMPLE
    Reset-ADUserPassword -UserName 'bob.jones'   
    Resets the AD account password for username bob.jones, and returns the new password
#>
function Reset-ADUserPassword
{
    [CmdletBinding()]
    param ( 
        [Parameter(Mandatory=$true,HelpMessage="Enter the username (samAccountName) of the account you want to reset the password for. The accountname format is firstname.lastname (e.g john.smith)")]
        [String]
        $UserName,

        [Parameter(Mandatory=$false,HelpMessage="Enter the new password or leave blank to automatically generate.")]
        [String]
        $NewPassword,

        [Parameter(Mandatory=$false,HelpMessage="Enter the new password as secure string or leave blank to automatically generate.")]
        [Security.SecureString]
        $NewSecurePassword
    )

    # Check whether the user exists
    $UserExist = Get-ADUser -Filter * -Properties * | where {$_.samAccountName -eq $UserName }

    if ($UserExist) 
    {
        write-verbose "Found useraccount to reset"
    }

    else
    {
        $Host.UI.WriteErrorLine("`nUnable to find user account.`nUser: $UserName`n") 
        Return 
    }    

    # Generate password and convert to secure string
    if ($NewPassword)
    {
        $NewSecurePassword = (ConvertTo-SecureString -AsPlainText $NewPassword -Force)
    }

    if (!($NewSecurePassword))
    {
        write-verbose "No Password specified"
        $RandomPassword = New-RandomComplexPassword
        $NewSecurePassword = (ConvertTo-SecureString -AsPlainText $RandomPassword -Force)
    }
    
    # Convert secure string
    $PasswordBSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($NewSecurePassword)

    # Get the plain text version of the password
    $PlainTextPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto($PasswordBSTR)

    # Clear password
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($PasswordBSTR)
    
    # Set AD Password
    try 
    {
        Set-ADAccountPassword -Identity $UserName -Reset -NewPassword $NewSecurePassword

        $NewPasswordInfo = [ordered] @{
                        UserName="$UserName";
                        NewPassword="$PlainTextPassword"
                    }

        $NewPasswordObj = New-Object -Type PSObject -Prop $NewPasswordInfo
    } 

    Catch [Microsoft.ActiveDirectory.Management.ADPasswordComplexityException]
    {
        $Host.UI.WriteErrorLine("`nPassword Does Not Meet Complexity Requirement.`nDomain Complexity Requirements:")
        Get-ADDomainPasswordRequirements
        Return
    }

    $NewPasswordObj
}
<#
.SYNOPSIS
    Get status of AD user account.
.DESCRIPTION
    Get status of AD user account including whether the account is enabled/disabled, whether the account is locked out (and when it was locked), when the last bad password was entered, whether the password is expired and when the password was last set. 
    Unlocks user account if locked out.
.PARAMETER UserName
    The user accountname (samAccountName) in the format of first.last (e.g john.smith).
.OUTPUTS
    Returns $UserStatusObj which is an array of PS objects containing the following information:
    Username:               The username (samAccountname) of the password that the password is being reset for.
    Enabled:                Whether the account is enabled or not (True/False).
    LastbadPasswordTime:    When the last bad password was entered.
    LockedOut:              Whether the account is locked out (True/False).
    LockOutTime:            What time the account was locked out.
    PasswordExpired:        Whether the current password has expired and requires changing (True/False)       
    PasswordLastSet:        When the password was last set.
.NOTES
    NAME......:  Get-ADUserStatus
    VERSION...:  1.0
    AUTHOR....:  Dan Stewart
    CREATED...:  4/7/15
.EXAMPLE
    Get-ADUserStatus -UserName 'john.smith'    
    Gets the account status for username john.smith
.EXAMPLE
    Get-ADUserStatus -UserName 'bob.jones' 
    Gets the account status for username bob.jones and if locked, unlocks the account.
#>
Function Get-ADUserStatus
{
    [CmdletBinding()]
    param ( 
        [Parameter(Mandatory=$true,HelpMessage="Enter the username (samAccountName) of the account you want to check status for. The accountname format is firstname.lastname (e.g john.smith)")]
        [String]
        $UserName
    )

    # Check whether the user exists
    $UserExist = Get-ADUser -Filter * -Properties * | where {$_.samAccountName -eq $UserName }

    if ($UserExist) 
    {
        write-verbose "Found useraccount to reset"
    }

    else
    {
        $Host.UI.WriteErrorLine("`nUnable to find user account.`nUser: $UserName`n") 
        Return 
    } 

    $Unlocked = $False

    if ($($UserExist.LockedOut) -eq $True )
    {        
        write-verbose "Account is locked out, unlocking."
        Unlock-ADAccount -Identity $Username
        $Unlocked = $True
    }

    else 
    {
        write-verbose "Account not locked."
    }

    $LockOutTime = [datetime]::FromFileTime("$($UserInfo.lockoutTime)").ToString("MM/dd/yyyy hh:mm:ss")
    $LastbadPasswordTime = [datetime]::FromFileTime("$($UserInfo.badPasswordTime)").ToString("MM/dd/yyyy hh:mm:ss")

    $UserStatusInfo = [ordered] @{
                        UserName="$UserName";
                        Enabled="$($UserExist.Enabled)";
                        LastbadPasswordAttempt = "$($UserExist.LastBadPasswordAttempt)";
                        LockedOut="$($UserExist.LockedOut)";
                        Unlocked="$Unlocked";
                        LockOutTime="$LockOutTime";
                        PasswordExpired="$($UserExist.PasswordExpired)";
                        PasswordLastSet="$($UserExist.PasswordLastSet)"
                    }

    $UserStatusObj = New-Object -Type PSObject -Prop $UserStatusInfo
    $UserStatusObj 
}




Function Test-ADUserCredentials 
{
    [CmdletBinding()]
    param ( 
        [Parameter(Mandatory=$true,HelpMessage="Enter the username (samAccountName) of the account you want to check the password for. The accountname format is firstname.lastname (e.g john.smith)")]
        [String]
        $UserName,

        [Parameter(Mandatory=$true,HelpMessage="Enter the password for the user account that you want to test the credentials for.")]
        [String]
        $Password

    )    

    $Domain = $(Get-ADDomain).dnsroot
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    
    $ContextType = [System.DirectoryServices.AccountManagement.ContextType]::Domain
    $PrincipleContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($ContextType, $Domain)

    $ValidatePasswordInfo = [ordered] @{
                        UserName="$UserName";
                        IsValid = $PrincipleContext.ValidateCredentials($Username, $Password).ToString()
                    }

    $ValidatePasswordObj = New-Object -Type PSObject -Prop $ValidatePasswordInfo
    $ValidatePasswordObj      
}
<#
.Synopsis
    Opens a dialog window that allows you to browse files and folders.
.DESCRIPTION
    Opens a dialog window that allows you to browse files and folders, you can apply filters to reduce the scope of the search and can enable multi-file select
.PARAMETER WindowTitle
    The title for the dialog window.
.PARAMETER InitialDirectory
    the path of the initial directory to start browing files from (default = $env:userprofile)
.PARAMETER FileTypeFilter
    The filter string must contain a description of the filter, followed by the vertical bar (|) and the filter pattern. The strings for different filtering options mu also be separated by the vertical bar. Example: Text files (*.txt)|*.txt|All files (*.*)|*.*)
.PARAMETER AllowMultiSelect
    The switch AllowMultiSelect is set, you can select multiple files from the browser window.
.OUTPUTS
    Returns a list of file(s) path's based on selection
.EXAMPLE
    Open-FileDialog -WindowTitle "Select File" -InitialDirectory $env:userprofile -FileTypeFilter 'CSV files (*.csv)|*.csv' 
    Opens a dialog window with the title "Select File" in the users default profile path. Filters files to only show .csv files. Does not allow for multi-selection of files.
.NOTES
    Script based on: http://blog.morg.nl/2014/01/generate-a-random-strong-password-in-powershell/
    (c) Morgan de Jonge CC BY SA
#>
function Open-FileDialog
{ 
    [CmdletBinding()]
    param (  
        [Parameter(Mandatory=$false,HelpMessage="Enter the title for the dialog window.")]
        [String]
        $WindowTitle,

        [Parameter(Mandatory=$true,HelpMessage="Enter the path of the initial directory to start browing files from.")]
        [String]
        $InitialDirectory = $env:userprofile,

        [Parameter(Mandatory=$true,HelpMessage="The filter string must contain a description of the filter, followed by the vertical bar (|) and the filter pattern. The strings for different filtering options mu also be separated by the vertical bar. Example: Text files (*.txt)|*.txt|All files (*.*)|*.*)")]
        [String]
        $FileTypeFilter,

        [Parameter(Mandatory=$false,HelpMessage="If the switch AllowMultiSelect is set, you can select multiple files from the browser window.")]
        [Switch]
        $AllowMultiSelect
    )

    Add-Type -AssemblyName System.Windows.Forms
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Title = $WindowTitle

    if (![string]::IsNullOrWhiteSpace($InitialDirectory)) 
    { 
        $openFileDialog.InitialDirectory = $InitialDirectory 
    }
    
    $openFileDialog.Filter = $FileTypeFilter
    
    if ($AllowMultiSelect) 
    { 
        $openFileDialog.MultiSelect = $true 
    }

    $openFileDialog.ShowHelp = $true    
    $openFileDialog.ShowDialog() > $null
    
    if ($AllowMultiSelect) 
    { 
        return $openFileDialog.Filenames 
    } 

    else 
    { 
        return $openFileDialog.Filename 
    }
}

#=========================================================[INITIALISATIONS]===========================================#
#=====================================================================================================================#
#Set Error Action, Verbose and Debug preferences
#$ErrorActionPreference = "SilentlyContinue"
$VerbosePreference = 'Continue'
#$DebugPreference = 'Continue'

#=========================================================[DECLARATIONS]==============================================#
#=====================================================================================================================#
$DisabledGroup = 'DISABLED_USERS'
$DisabledOU = 'OU=_USERS,OU=zzDISABLED_USERS,DC=glassdoor,DC=ad'
$DaysToDelete = 30
$CompanyName = 'Glassdoor, Inc'
$EmailDomainName = 'glassdoor.com'
$GroupPrefix = 'ALL_'
$RootPath = "OU=GD_USERS,DC=glassdoor,DC=ad"
$UsersOU = "OU=_USERS"
$ComputersOU = "OU=_COMPUTERS"
$StandardGroups = "GDBoxUsers,GDConfluenceUsers,GDOktaUsers,APP_Zendesk_Users"
$NewUsersFolder =  $env:userprofile + '\Documents\NewUsers\'

#===========================================================[EXECUTION]===============================================#
#=====================================================================================================================#

Clear
# Check whether output folder exists, if not create
if(!(Test-Path $NewUsersFolder))
{
    New-Item $NewUsersFolder -type directory | out-null
    write-verbose "Output folder does not exist, created: $NewUsersFolder"
}

# Launch menu
[int]$AccountAction = 0
while ($AccountAction -lt 1 -or $AccountAction -gt 5 )
{
    write-host "`nAD Account Management Select Action:"  -foregroundcolor yellow
    write-host "------------------------------------`n" -foregroundcolor yellow
    Write-host "1. Create New User (manually) " -foregroundcolor cyan
    Write-host "2. Create New Users/Update Existing Users Information (from .csv)" -foregroundcolor cyan    
    Write-host "3. Disable User" -foregroundcolor cyan
    Write-host "4. Reset User Password" -foregroundcolor cyan
    Write-host "5. Check User Status (unlocks account if locked)" -foregroundcolor cyan

    [console]::ForegroundColor = "cyan"
    [Int]$AccountAction = read-host -prompt "`nSelection"
    [console]::ResetColor()
}

# Create new User
if ($AccountAction -eq 1)
{
    write-host "`nPlease Enter New Users Information at Prompts:" -foregroundcolor yellow
    write-host "----------------------------------------------`n" -foregroundcolor yellow
    [console]::ForegroundColor = "cyan"
    $FirstName = (Read-Host "First Name")
    $FirstName = $FirstName.trim()
    $FirstName = (Get-Culture).textinfo.totitlecase($FirstName.tolower())
    $LastName = (Read-Host "Last Name")
    $LastName = $LastName.trim()
    $LastName = (Get-Culture).textinfo.totitlecase($LastName.tolower())
    $AssetTag = (Read-Host "Laptop Asset Tag Number")
    [console]::ResetColor()

    [int]$LaptopChoice = 0
    while ($LaptopChoice-lt 1 -or $LaptopChoice -gt 4 )
    {
        write-host "`nSelect Laptop Type:"  -foregroundcolor yellow
        write-host "-------------------`n" -foregroundcolor yellow
        Write-host "1. Macbook Air 13`"" -foregroundcolor cyan
        Write-host "2. Macbook Pro 15`"" -foregroundcolor cyan
        Write-host "3. Lenovo Thinkpad x240" -foregroundcolor cyan
        Write-host "4. Lenovo Thinkpad T540p" -foregroundcolor cyan

        [console]::ForegroundColor = "cyan"
        [Int]$LaptopChoice = read-host -prompt "`nLaptop Type"
        [console]::ResetColor()
    }

    if ($LaptopChoice -eq 1)
    {
        $LaptopType = 'Macbook Air'
    }

    elseif ($LaptopChoice -eq 2)
    {
        $LaptopType = 'Macbook Pro'
    }

    elseif ($LaptopChoice -eq 3)
    {
        $LaptopType = 'Thinkpad x240'
    }

    elseif ($LaptopChoice -eq 4)
    {
        $LaptopType = 'Thinkpad T540p'
    }

    # Prompt for Department Name
    [int]$MenuChoice = 0
    while ($MenuChoice-lt 1 -or $MenuChoice -gt 19 )
    {
        write-host "`nSelect Department:"  -foregroundcolor yellow
        write-host "------------------`n" -foregroundcolor yellow
        Write-host "1. B2B Marketing" -foregroundcolor cyan
        Write-host "2. Business Development" -foregroundcolor cyan
        Write-host "3. Client Services" -foregroundcolor cyan
        Write-host "4. Content Operations" -foregroundcolor cyan        
        Write-host "5. Consumer Marketing" -foregroundcolor cyan
        Write-host "6. Data Science" -foregroundcolor cyan
        Write-host "7. Engineering" -foregroundcolor cyan
        Write-host "8. Executive" -foregroundcolor cyan
        Write-host "9. Facilities" -foregroundcolor cyan
        Write-host "10. Finance" -foregroundcolor cyan
        Write-host "11. Human Resources" -foregroundcolor cyan
        Write-host "12. IT" -foregroundcolor cyan
        Write-host "13. Jobs and Search" -foregroundcolor cyan
        Write-host "14. Legal" -foregroundcolor cyan
        Write-host "15. Product Mgmt and Design" -foregroundcolor cyan
        Write-host "16. Public Relations" -foregroundcolor cyan
        Write-host "17. Recruiting" -foregroundcolor cyan
        Write-host "18. Sales - Employer" -foregroundcolor cyan
        Write-host "19. Sales - Lead Development" -foregroundcolor cyan

        [console]::ForegroundColor = "cyan"
        [Int]$MenuChoice = read-host -prompt "`nSelection"
        [console]::ResetColor()
    }

    if ($MenuChoice -eq 1)
    {
        $Department = 'B2B Marketing'
    }

    elseif ($MenuChoice -eq 2)
    {
        $Department = 'Business Development'
    }

    elseif ($MenuChoice -eq 3)
    {
        $Department = 'Client Services'
    }

    elseif ($MenuChoice -eq 4)
    {
        $Department = 'Consumer Marketing'
    }

    elseif ($MenuChoice -eq 5)
    {
        $Department = 'Content Operations'
    }

    elseif ($MenuChoice -eq 6)
    {
        $Department = 'Data Science'
    }

    elseif ($MenuChoice -eq 7)
    {
        $Department = 'Engineering'
    }

    elseif ($MenuChoice -eq 8)
    {
        $Department = 'Executive'
    }

    elseif ($MenuChoice -eq 9)
    {
        $Department = 'Facilities'
    }

    elseif ($MenuChoice -eq 10)
    {
        $Department = 'Finance'
    }

    elseif ($MenuChoice -eq 11)
    {
        $Department = 'Human Resources'
    }

    elseif ($MenuChoice -eq 12)
    {
        $Department = 'IT'
    }

    elseif ($MenuChoice -eq 13)
    {
        $Department = 'Jobs and Search'
    }

    elseif ($MenuChoice -eq 14)
    {
        $Department = 'Legal'
    }

    elseif ($MenuChoice -eq 15)
    {
        $Department = 'Product Mgmt and Design'
    }

    elseif ($MenuChoice -eq 16)
    {
        $Department = 'Public Relations'
    }

    elseif ($MenuChoice -eq 17)
    {
        $Department = 'Recruiting'
    }

    elseif ($MenuChoice -eq 18)
    {
        $Department = 'Sales Employer'
    }

    elseif ($MenuChoice -eq 19)
    {
        $Department = 'Sales Lead Development'
    }

    write-host "`nPlease Review the Information Entered:" -foregroundcolor yellow
    write-host "--------------------------------------`n" -foregroundcolor yellow
    write-host "First Name:  " -foregroundcolor cyan -nonewline
    write-host "$FirstName" -foregroundcolor blue
    write-host "Last Name :  " -foregroundcolor cyan -nonewline
    write-host "$LastName" -foregroundcolor blue
    write-host "Department:  " -foregroundcolor cyan -nonewline
    write-host "$Department" -foregroundcolor blue
    write-host "Laptop Type: " -foregroundcolor cyan -nonewline
    write-host "$LaptopType" -foregroundcolor blue
    write-host "Asset Tag :  " -foregroundcolor cyan -nonewline
    write-host "$AssetTag`n" -foregroundcolor blue


    $Password = New-RandomComplexPassword
    $Prompttitle = ""

    [console]::ForegroundColor = "cyan"
    write-host "`nConfirm That This is Correct ?" -foregroundcolor yellow
    [console]::ResetColor()

    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Create User With This Information."
    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "There is a Mistake, I Need to Re-Enter the Information."
    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
    $Proceed = $host.ui.PromptForChoice($Prompttitle, $message, $options, 1) 

    switch ($Proceed)
    {
        0 
        {
            # Create new user
            write-host "`nCreating New User Account`n"
            $DepartmentNameUpdate = $($Department) -Replace(" - "," ")
            $DepartmentNameUpdated = $($DepartmentNameUpdate).Replace(" ","_")
            $UserPath = $($UsersOU + ",OU=$DepartmentNameUpdated," + $RootPath)
            $NewUser = New-ADUserAccount -FirstName $FirstName -LastName $LastName -Department $Department -Path $UserPath 

            # Create computer 
            $ComputerPath = $($ComputersOU + ",OU=$DepartmentNameUpdated," + $RootPath)
            $NewComputer = New-ADComputerAccount -UserName $($NewUser.samAccountname) -Path $ComputerPath -AssetTag $AssetTag -LaptopType $LaptopType
        
            $UserInfo = [ordered]  @{
                        FirstName="$FirstName";
                        LastName="$LastName";
                        Department="$Department";
                        UserName="$($NewUser.samAccountname)";
                        EmailAddress="$($NewUser.EmailAddress)";
                        Password="$($NewUser.password)";
                        UserPath="$($NewUser.UserPath)";
                        MemberOfGroups="$($Memberof -join ",")";
                        ComputerName="$($NewComputer.ComputerName)";
                        ComputerType="$($NewComputer.ComputerType)";
                        ComputerPath="$($NewComputer.ComputerPath)";
                    }
            $UserObj = New-Object -Type PSObject -Prop $UserInfo
            $UserObj      
        }

        1 
        {
            write-host "`nPlease Re-Enter the Information`n"
            .\UserPrmompt.ps1
        }
    }
}

# Create/Update bulk users
if ($AccountAction -eq 2)
{
    write-host "`nBulk User Creation/Update. Please select .csv File Containing Users Information from HR:"  -foregroundcolor yellow
    write-host "----------------------------------------------------------------------------------------`n" -foregroundcolor yellow

    start-sleep -s 1
    $Filter = 'CSV files (*.csv)|*.csv'

    $SelectCSVFile = Open-FileDialog -WindowTitle "Select .CSV file to Create Users From" -InitialDirectory $env:userprofile -FileTypeFilter $Filter 

    if (![string]::IsNullOrEmpty($SelectCSVFile)) 
    { 
        Write-Host "`nCreating users from: $SelectCSVFile`n" -foregroundcolor green
        $Users = Import-Csv $SelectCSVFile
    }

    else 
    { 
        Write-Host "`nYou did not select a file.`n" -foregroundcolor red
        Return
    }

    foreach ($User in $Users)
    {
        # Define first name based on whether prefered name is included in HR .csv
        if ($($User."HRPreferedName")) 
        {
            $OtherName = $($User."HRFirstName")  
            $FirstName = $($User."HRPreferedName")
        }

        else 
        {
            $FirstName = $($User."HRFirstName")           
        }

        $LastName = $($User."HRLastName")

        # Split Department string to obtain Department ID and Department Name    
        [int]$DepartmentID = $($($User."HRDepartment") -split (" ",2))[0]
        $Department = $($($User."HRDepartment") -split (" ",2))[-1]

        write-host "`nChecking User: $($FirstName + '.' + $LastName)" -foregroundcolor cyan


        $UserExist = (Get-ADUser -Filter * | where {$_.samAccountName -like $($FirstName + '.' + $LastName) -or $_.mail -like $($FirstName + '.' + $LastName + '@' + $EmailDomainName) })

        if($UserExist)
        {
            write-host "User account already exists." -foregroundcolor green
            $NewUser = $UserExist
        }

        else 
        {
            # If the user does not exist
            write-host "User account does not exist. Creating account`n" -foregroundcolor cyan
            
            # Parse department name and replace spaces and dashes with underscores
            $DepartmentNameUpdate = $($Department) -Replace(" - "," ")
            $DepartmentNameUpdated = $($DepartmentNameUpdate).Replace(" ","_")
            $UserPath = $($UsersOU + ",OU=$DepartmentNameUpdated," + $RootPath)
            
            $NewUser = New-ADUserAccount -FirstName $FirstName -LastName $LastName -Department $Department -Path $UserPath
            
            $ComputerPath = $($ComputersOU + ",OU=$DepartmentNameUpdated," + $RootPath)
            $NewComputer = New-ADComputerAccount -UserName $($NewUser.samAccountname) -Path $ComputerPath -AssetTag $($User.ITAssetTag) -LaptopType $($User.ITLaptopType)

            # Validate that account group exists
            if (!(Get-ADGroup -Filter * | where {$_.name -like $($GroupPrefix + $DepartmentNameUpdated) } ))
            {
                $Host.UI.WriteErrorLine("`nThe AD group does not exist, please check in AD.`nGroup name = $($GroupPrefix + $DepartmentNameUpdated)`n") 
            }

            else 
            {
                # Add user to department security group
                write-verbose "AD Group does exist. Group name = $($GroupPrefix + $DepartmentName)" 
                Add-ADGroupMember -Identity $($GroupPrefix + $DepartmentNameUpdated) -Member $($NewUser.samAccountname)
                write-verbose "Added user: $SamAccountName to AD group: $($GroupPrefix + $DepartmentNameUpdated)"    
       
            } 

            # Add to standard groups
            foreach ($StandardGroup in $StandardGroups.split(","))
            {
                Add-ADGroupMember -Identity $StandardGroup -Member $($NewUser.samAccountname)
            }

            $Memberof = @()
            $MemberOfGroups = Get-ADUser -Identity $($NewUser.samAccountname) -Properties * | select -expand memberof
            
            foreach ($MemberOfGroup in $MemberOfGroups)
            {
                $GroupName = $MemberOfGroup -replace '^CN=(.+?),(?:OU|CN)=.+','$1'
                $Memberof += $GroupName 
            }

            $UserInfo = [ordered]  @{
                        FirstName="$FirstName";
                        LastName="$LastName";
                        Department="$Department";
                        UserName="$($NewUser.samAccountname)";
                        EmailAddress="$($NewUser.EmailAddress)";
                        Password="$($NewUser.password)";
                        UserPath="$($NewUser.UserPath)";
                        MemberOfGroups="$($Memberof -join ",")";
                        ComputerName="$($NewComputer.ComputerName)";
                        ComputerType="$($NewComputer.ComputerType)";
                        ComputerPath="$($NewComputer.ComputerPath)";
                    }
            $UserObj = New-Object -Type PSObject -Prop $UserInfo
            $UserObj 
             
            $NewUsersOutfile = $NewUsersFolder + "NewUsers_$(Get-Date -UFormat %d%m%y ).csv"
            $UserObj | export-csv $NewUsersOutfile -NoTypeInformation -Append
        }

        write-host "`nUpdating AD attributes: `n" -foregroundcolor cyan

        if ($($User."HRSupervisor"))
        {
            $SupervisorFirst = $($($User."HRSupervisor") -split(",")).trim()[1]
            $SupervisorLast = $($($User."HRSupervisor") -split(",")).trim()[0]
            $SupervisorADName = $SupervisorFirst + '.' + $Supervisorlast
            $Manager = Get-ADUser -Identity $SupervisorADName
        } 

        if ($($User."HRAddress") -eq 'Office - US - OH')
        {
            $Office = 'Ohio'
            $City = 'Uniontown'
            $Street = '1505 Corporate Woods Pkwy, Suite 600'
            $State = 'OH'
            $Country = 'United States'
            $Zip = 44685
            $CountryCode = 840
            $CountryAbrev = 'US'
        }

        elseif ($($User."HRAddress") -eq 'Office - US - CA - Mill Valley')
        {
            $Office = 'Mill Valley'
            $City = 'Mill Valley'
            $Street = '100 Shoreline Hwy, Bldg A'
            $State = 'CA'
            $Country = 'United States'
            $Zip = 94941
            $CountryCode = 840
            $CountryAbrev = 'US'
        }

        elseif ($($User."HRAddress") -eq 'Office - UK - London')
        {
            $Office = 'London'
            $City = 'London'
            $Street = '48 Charlotte St.,Fitzrovia'
            $State = 'London'
            $Country = 'United Kingdom'
            $Zip = 'W1T UK'
            $CountryCode = 826
            $CountryAbrev = 'UK'    
        }

        else 
        {
            $Office= 'Remote'
            $City = 'Remote'
            $Street = 'Remote'
            $State = $($User."HRState")
            $Country = 'United States'
            $Zip = 11111
            $CountryCode = 840
            $CountryAbrev = 'US'        
        }


        $Homepage = 'www.' + $EmailDomainName

        #write-verbose "`nTab1`n" -foregroundcolor cyan
        write-verbose "FirstName: $FirstName"
        write-verbose "LastName: $LastName"
        write-verbose "DisplayName: $($NewUser.DisplayName)"
        write-verbose "Description: $($User."HRJobTitle")"
        write-verbose "Office: $JobTitle" 
        write-verbose "Work Phone: $WorkPhone"
        write-verbose "Email: $($NewUser.mail)" 
        write-verbose "Homepage: $Homepage"

        #write-verbose "`nTab2-Address`n" -foregroundcolor cyan
        write-verbose "Office: $Office"
        write-verbose "Street: $Street"
        write-verbose "City: $City"
        write-verbose "State: $State"
        write-verbose "Zip: $Zip"
        write-verbose "Country: $Country"
        write-verbose "CountryCode: $CountryCode"

        write-verbose "samAccountName: $($NewUser.samAccountName)"
        write-verbose "UPN: $($NewUser.UserPrincipalName)"    
        write-verbose "Job Title: $($User."HRJobTitle")"
        write-verbose "Department: $Department"
        write-verbose "Company: $CompanyName"
        write-verbose "Supervisor: $SupervisorADName"
        write-verbose "EmployeeID: $($User."HREEID")"
        write-verbose "EmployeeType: $($User."HREEType")"
        #write-verbose "Mobile: $MobilePhone"

        # Clear all fields to ensure that you can add new data
        set-aduser -Identity $($NewUser.samAccountname) -clear EmployeeID,Employeetype,c,Co,Company,Department,description,departmentNumber,l,Manager,mobile,physicalDeliveryOfficeName,PostalCode,st,StreetAddress,telephoneNumber,Title,wWWHomePage

        # Add data to all fields
        Set-ADUser -Identity $($NewUser.samAccountname) -add @{ employeeID="$($User."HREEID")"; employeetype="$($User."HREEType")"; Description="$($User."HRJobTitle")"; Title="$($User."HRJobTitle")"; manager="$Manager"; Department="$department"; departmentnumber="$DepartmentID"; Company="$CompanyName"; physicalDeliveryOfficeName="$Office"; streetAddress="$Street"; l="$City"; st="$State"; postalCode="$Zip"; co="$Country"; c="$CountryAbrev"; wWWHomePage="$Homepage" }
        
        # Update country code, this attribute appears to be a little buggy, so can't be cleared
        Set-ADUser -Identity $($NewUser.samAccountname) -replace @{ countryCode="$CountryCode" }
        
        if ($User."HRMobilePh")
        {
            Set-ADUser -Identity $($NewUser.samAccountname) -add @{ mobile="$($User."HRMobilePh")" }
            write-verbose "Adding Mobilephone Number: $($User."HRMobilePh")"
        }

        if ($User."HRworkPh")
        {
            Set-ADUser -Identity $($NewUser.samAccountname) -add @{ telephoneNumber="$($User."HRworkPh")" }
            write-verbose "Adding Work Phone Number: $($User."HRworkPh")"
        }
    }
}

# Disable user
if ($AccountAction -eq 3)
{
    write-host "`nDisable AD User Account"  -foregroundcolor yellow
    write-host "-----------------------`n" -foregroundcolor yellow
    [console]::ForegroundColor = "cyan"
    $UserNameToDisable = (Read-Host "Enter Username to Disable")
    $UserNameToDisable = $UserNameToDisable.trim()
    [console]::ResetColor()
    
    Disable-ADUser -UserNameToDisable $UserNametoDisable -DisabledGroup $DisabledGroup -DisabledOU $DisabledOU -DaysToDelete $DaysToDelete
}

# Reset user password
if ($AccountAction -eq 4)
{
    write-host "`nReset AD User Password"  -foregroundcolor yellow
    write-host "----------------------`n" -foregroundcolor yellow
    [console]::ForegroundColor = "cyan"
    $UserName = (Read-Host "Enter Username for Password Reset")
    $UserName = $UserName.trim()
    [console]::ResetColor()

    [int]$PasswordAction = 0
    while ($PasswordAction -lt 1 -or $PasswordAction -gt 2 )
    {
        write-host "`nHow Do You Want to Reset the Users Password ?"  -foregroundcolor yellow
        write-host "---------------------------------------------`n" -foregroundcolor yellow
        Write-host "1. Automatically Generate New Random Password" -foregroundcolor cyan
        Write-host "2. Manually Enter A New Password" -foregroundcolor cyan
        [console]::ForegroundColor = "cyan"
        [Int]$PasswordAction = read-host -prompt "`nPassword Reset"
        [console]::ResetColor()
    }

    if ($PasswordAction -eq 1)
    {
        Reset-ADUserPassword -UserName $UserName
    }

    if ($PasswordAction -eq 2)
    {
        [console]::ForegroundColor = "cyan"
        $NewSecurePassword = Read-Host -Prompt "Enter the new password" -AsSecureString
        [console]::ResetColor()

        Reset-ADUserPassword -Username $UserName -NewSecurePassword $NewSecurePassword
    }
}

# Check user and unlock account
if ($AccountAction -eq 5)
{
    write-host "`nCheck User Status and Unlock"  -foregroundcolor yellow
    write-host "----------------------------`n" -foregroundcolor yellow
    [console]::ForegroundColor = "cyan"
    $UserName = (Read-Host "Enter Username to Check")
    $UserName = $UserName.trim()
    [console]::ResetColor()

    Get-ADUserStatus -Username $UserName
}
