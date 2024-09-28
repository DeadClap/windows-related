# Function to get sub-OUs under the "Accounts" OU but exclude the Accounts OU itself
function Get-SubOUsInAccountsOU {
    $ouPath = "OU=Accounts,DC=yourdomain,DC=com"  # Replace with your domain's base path
    $subOUs = Get-ADOrganizationalUnit -Filter * -SearchBase $ouPath | Where-Object { $_.DistinguishedName -ne "OU=Accounts,DC=yourdomain,DC=com" }
    return $subOUs
}

# Function to extract and display the OU names in a readable format
function Show-OUMenu {
    $subOUs = Get-SubOUsInAccountsOU
    $counter = 1
    foreach ($ou in $subOUs) {
        # Extract just the OU name (everything after "OU=" and before the next comma)
        $ouName = ($ou.DistinguishedName -split ',')[0] -replace '^OU='
        Write-Host "$counter. $ouName"
        $counter++
    }
    $selection = Read-Host "Enter the number corresponding to the OU you want to create accounts in"
    return $subOUs[$selection - 1].DistinguishedName
}

# Function to create a new Active Directory user
function Create-NewADUser {
    $ouDistinguishedName = Show-OUMenu

    # Collect user information
    $firstName = Read-Host "Enter First Name"
    $middleInitial = Read-Host "Enter Middle Initial (or leave blank)"
    $lastName = Read-Host "Enter Last Name"
    
    # Generate a random password
    $password = [System.Web.Security.Membership]::GeneratePassword(12, 2)
    Write-Output "$firstName $lastName: $password" | Out-File -Append -FilePath "C:\Path\To\Your\File.txt"  # Change the file path as needed

    # Construct the display name
    if (-not [string]::IsNullOrWhiteSpace($middleInitial)) {
        $displayName = "$lastName, $firstName $middleInitial"
    } else {
        $displayName = "$lastName, $firstName"
    }

    # Determine username prefix based on OU
    $ouName = ($ouDistinguishedName -split ',')[0] -replace '^OU='
    $username = ""

    switch ($ouName) {
        "Domain Admins" { $username = "da-$firstName$lastName" }
        "Server Users" { $username = "su-$firstName$lastName" }
        "Service Accounts" { $username = "svc-$firstName$lastName" }
        "Workstation Admins" { $username = "wsadm-$firstName$lastName" }
        "Contractor" { $username = "$firstName$lastName" }
        "Full Time Employee" { $username = "$firstName$lastName" }
        "Vendor" { $username = "$firstName$lastName" }
        default { $username = "$firstName$lastName" }  # No prefix for unknown OUs
    }

    # Create the new AD user
    New-ADUser -Name $displayName -GivenName $firstName -Surname $lastName -SamAccountName $username `
               -UserPrincipalName "$username@yourdomain.com" -Path $ouDistinguishedName `
               -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) `
               -Enabled $true -PasswordNeverExpires $false -ChangePasswordAtLogon $true

    Write-Host "User $displayName created successfully with username: $username"
}

# Call the function to create a new AD user
Create-NewADUser
