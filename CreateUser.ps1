# Import Active Directory module
Import-Module ActiveDirectory

# Function to generate a random password
function Generate-RandomPassword {
    $length = 12
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
    $password = -join ((65..90) + (97..122) + (48..57) + 33..38 | Get-Random -Count $length | ForEach-Object { [char]$_ })
    return $password
}

# Function to get sub-OUs under the "Accounts" OU
function Get-SubOUsInAccountsOU {
    $ouPath = "OU=Accounts,DC=yourdomain,DC=com"  # Replace with your domain's base path
    $subOUs = Get-ADOrganizationalUnit -Filter * -SearchBase $ouPath | Where-Object { $_.DistinguishedName -notlike "*Accounts,DC=yourdomain,DC=com" }
    return $subOUs
}

# Function to display a menu of sub-OUs and allow selection
function Show-OUMenu {
    $subOUs = Get-SubOUsInAccountsOU
    $counter = 1
    foreach ($ou in $subOUs) {
        Write-Host "$counter. $($ou.DistinguishedName)"
        $counter++
    }
    $selection = Read-Host "Enter the number corresponding to the OU you want to create accounts in"
    return $subOUs[$selection - 1].DistinguishedName
}

# Function to add a prefix to usernames based on the OU
function Add-PrefixBasedOnOU($ouDistinguishedName, $username) {
    switch -regex ($ouDistinguishedName) {
        ".*Domain Admins.*"    { return "da-" + $username }
        ".*Server Users.*"     { return "su-" + $username }
        ".*Service Accounts.*" { return "svc-" + $username }
        ".*Workstation Admins.*" { return "wsadm-" + $username }
        ".*Employees.*"        { return $username }  # No prefix for Employees and its sub-OUs
        default { return $username }  # No prefix if no matching OU
    }
}

# Get selected OU
$selectedOU = Show-OUMenu

# Output file path to store the username:password entries
$outputFile = "C:\Users\Public\user_accounts.txt"  # Specify the path where the file will be saved
Clear-Content $outputFile -ErrorAction SilentlyContinue  # Clear the file if it already exists

# Loop to create multiple accounts
$numberOfAccounts = Read-Host "How many accounts do you want to create?"
for ($i = 1; $i -le $numberOfAccounts; $i++) {
    $firstName = Read-Host "Enter First Name for User $i"
    $middleInitial = Read-Host "Enter Middle Initial for User $i (Press Enter to skip)"
    $lastName = Read-Host "Enter Last Name for User $i"

    # Generate username based on whether middle initial is provided
    if ($middleInitial) {
        $username = $firstName.Substring(0, 1) + $middleInitial.Substring(0, 1) + $lastName
        $displayName = "$lastName, $firstName $middleInitial"
    } else {
        $username = $firstName.Substring(0, 1) + $lastName
        $displayName = "$lastName, $firstName"
    }

    # Add prefix to username based on the selected OU
    $prefixedUsername = Add-PrefixBasedOnOU $selectedOU $username

    # Generate a random password
    $password = Generate-RandomPassword
    Write-Host "Generated Password for $prefixedUsername: $password"

    # Create user in selected OU based on presence of middle initial
    if ($middleInitial) {
        # Create user with middle initial
        New-ADUser `
            -Name $displayName `
            -GivenName $firstName `
            -Initials $middleInitial `
            -Surname $lastName `
            -SamAccountName $prefixedUsername `
            -UserPrincipalName "$prefixedUsername@yourdomain.com" `
            -Path $selectedOU `
            -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) `
            -Enabled $true
    } else {
        # Create user without middle initial
        New-ADUser `
            -Name $displayName `
            -GivenName $firstName `
            -Surname $lastName `
            -SamAccountName $prefixedUsername `
            -UserPrincipalName "$prefixedUsername@yourdomain.com" `
            -Path $selectedOU `
            -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) `
            -Enabled $true
    }

    # Set the user to reset password on first logon
    Set-ADUser $prefixedUsername -ChangePasswordAtLogon $true

    # Append the username and password to the output file
    Add-Content -Path $outputFile -Value "$prefixedUsername:$password"

    Write-Host "User $prefixedUsername created successfully in $selectedOU"
}

Write-Host "All accounts created successfully!"
Write-Host "Usernames and passwords have been saved to: $outputFile"
