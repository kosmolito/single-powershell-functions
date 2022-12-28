
function New-KSADUser {
    [CmdletBinding()]
    param(
        [Parameter()][string]$FirstName,
        [Parameter()][String]$LastName,
        [Parameter()][String]$UserPassword,
        [Parameter()][String]$OU,
        [Parameter()][String]$DomainName,
        [Parameter()][string]$SecurityGroups,
        [Parameter()][String]$UserName
        )

    $FullName = $FirstName + " " + $LastName

    # If UserName / SamAccount is not provided, the firstname and last name with a dot will be set
    # as SamAccountName / UserName
    if (!($UserName)) {
        $UserName = ("$($FirstName)".ToLower() + "." + "$($LastName)".ToLower())

    } else {
        $UserName = $UserName.ToLower()
    }

    # Converting non [a-z] charactor for the username to [a-z]
    # The string has been converted to Char array and the each char is been checked.
    # If its find å ä or ö it will convert to [a-z] letters.
    # TempUsername has $null value at the beginning. Char are been added to the variable on every loop.
    $TempUserName = $null
    foreach ($Char in $UserName.ToCharArray()) {
        switch -Regex ($Char) {
            [åäæ] { $Char = "a" }
            [öø] { $Char = "o" }
        }
        $TempUserName += $Char
    }
    $UserName = $TempUserName


    $SecurityGroups = $SecurityGroups.split(",")
    $DomainDistinguishedName = (get-addomain).distinguishedname

    if ($PSBoundParameters.ContainsKey("UserOU")) {
    $UserOU = "Users"    
    if (-not (Get-ADOrganizationalUnit -Filter 'name -like $OU'))
        { New-ADOrganizationalUnit -Name $OU -Path "$DomainDistinguishedName" -ProtectedFromAccidentalDeletion $false }

    # Creat OU for Sec groups
    $SecurityGroupOU = "SEC_Groups"
    if (-not (Get-ADOrganizationalUnit -Filter 'name -like $SecurityGroupOU'))
    { New-ADOrganizationalUnit -Name $SecurityGroupOU -Path "$DomainDistinguishedName" -ProtectedFromAccidentalDeletion $false }
    
    if (-not (Get-ADOrganizationalUnit -filter 'name -like $UserOU' | Where-Object {$_.DistinguishedName -match "OU=$OU,$DomainDistinguishedName"}) ) 
                { New-ADOrganizationalUnit -Name $UserOU -Path "OU=$OU,$DomainDistinguishedName" -ProtectedFromAccidentalDeletion $false }
    $UserOUPath = "OU=$UserOU,OU=$OU,$DomainDistinguishedName"
    } else {
        $UserOUPath = "CN=Users,$DomainDistinguishedName"
    }


    if($PSBoundParameters.ContainsKey("SecurityGroups")) {

        # Adding One extra SEC Group for each OU to easier NTFS target
        $SecurityGroups = $SecurityGroups + "SEC_$OU"

        $TempSecGroups = $null
        foreach ($Group in $SecurityGroups) {
            if (!($Group -match "^SEC_")) {
                $Group = "SEC_" + $Group
            }
            [array]$TempSecGroups = $TempSecGroups + $Group
        }
        
        $SecurityGroups = $TempSecGroups

        foreach ($SecurityGroup in $SecurityGroups) {
            if (-not (Get-ADGroup -Filter 'Name -like $SecurityGroup')) 
            { New-ADGroup -Name $SecurityGroup -GroupCategory Security -GroupScope Global -Path "OU=$SecurityGroupOU,$DomainDistinguishedName" }    
        }
    }

    # If Password not provided, the password will be set as Mov2022
    if ($PSBoundParameters.ContainsKey("UserPassword")) {
        $Password = ConvertTo-SecureString $UserPassword -AsPlainText -Force
    } else {
        $Password = ConvertTo-SecureString "Move2022" -AsPlainText -Force
    }

    New-AdUser -AccountPassword $Password `
    -GivenName $FirstName `
    -Surname $LastName `
    -DisplayName $FullName `
    -Name $FullName `
    -SamAccountName $username `
    -UserPrincipalName $username"@"$DomainName `
    -PasswordNeverExpires $true `
    -Path $UserOUPath `
    -Enabled $true

    # Add User to Security Group if Security Grup information is provided
    if ($PSBoundParameters.ContainsKey("SecurityGroups")) {
        # -Path "ou=$OU,$(([ADSI]`"").distinguishedName)" `
        foreach ($SecurityGroup in $SecurityGroups) {
            Add-ADGroupMember -Identity $SecurityGroup -Members $username
        }
    }
}