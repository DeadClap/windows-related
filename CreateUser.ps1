# Define domain and OU path variables
$domainName = "yourdomain"  # Replace with your actual domain name
$topLevelDomain = "com"      # Replace with your actual top-level domain
$domain = "$domainName.$topLevelDomain"
$ouPath = "OU=Accounts,DC=$domainName,DC=$topLevelDomain"  # OU path for Accounts
$groupsOUPath = "OU=Groups,DC=$domainName,DC=$topLevelDomain"  # OU path for Groups

# Function to get sub-OUs under the "Accounts" OU but exclude the Accounts OU itself
function Get-SubOUsInAccountsOU {
    $subOUs = Get-ADOrganizationalUnit -Filter * -SearchBase $ouPath | Where-Object { $_.DistinguishedName -ne "OU=Accounts,DC=$domainName,DC=$topLevelDomain" }
    return $subOUs
}

# Function to get groups in the Groups OU and its Sub-OUs
function Get-GroupsInOU {
    $groups = Get-ADGroup -Filter * -SearchBase $groupsOUPath
    return $groups
}

# Function to toggle group membership for a user
function Toggle-GroupMembership {
    $username = Read-Host "Enter the username of the account"
    if (-not $username) { Show-MainMenu }

    $groups = Get-GroupsInOU

    Write-Host "Available Groups:"
    $counter = 1
    foreach ($group in $groups) {
        Write-Host "$counter. $($group.Name)"
        $counter++
    }

    $groupSelection = Read-Host "Select a group by number to toggle membership"
    if (-not $groupSelection) { Show-MainMenu }
    
    $selectedGroup = $groups[$groupSelection - 1]

    # Check if user is already a member of the selected group
    $isMember = Get-ADGroupMember -Identity $selectedGroup.Name | Where-Object { $_.SamAccountName -eq $username }

    if ($isMember) {
        # If the user is a member, remove them from the group
        Remove-ADGroupMember -Identity $selectedGroup.Name -Members $username -Confirm:$false
        Write-Host "$username has been removed from the group $($selectedGroup.Name)."
    } else {
        # If the user is not a member, add them to the group
        Add-ADGroupMember -Identity $selectedGroup.Name -Members $username
        Write-Host "$username has been added to the group $($selectedGroup.Name)."
    }
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
    if (-not $selection) { Show-MainMenu }
    return $subOUs[$selection - 1].DistinguishedName
}

# Function to create a new Active Directory user
function Create-NewADUser {
    $ouDistinguishedName = Show-OUMenu

    # Determine the type of account being created
    $accountType = Read-Host "Is this a Service Account? (yes/no)"
    if (-not $accountType) { Show-MainMenu }

    if ($accountType -eq "yes") {
        # Collect service name for service accounts
        $serviceName = Read-Host "Enter Service Name"
        if (-not $serviceName) { Show-MainMenu }

        # Generate a random password
        $password = [System.Web.Security.Membership]::GeneratePassword(12, 2)

        # Output the service name and password to a text file
        $username = "svc-$serviceName"
        Write-Output "$username - $password" | Out-File -Append -FilePath "C:\Path\To\Your\File.txt"  # Change the file path as needed

        # Create the new Service Account user
        New-ADUser -Name $serviceName -SamAccountName $username `
                   -UserPrincipalName "$username@$domain" -Path $ouDistinguishedName `
                   -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) `
                   -Enabled $true -PasswordNeverExpires $false -ChangePasswordAtLogon $true

        Write-Host "Service Account $serviceName created successfully with username: $username"
    } else {
        # Collect user information for regular accounts
        $firstName = Read-Host "Enter First Name"
        if (-not $firstName) { Show-MainMenu }

        $middleInitial = Read-Host "Enter Middle Initial (or leave blank)"
        $lastName = Read-Host "Enter Last Name"
        if (-not $lastName) { Show-MainMenu }

        # Generate a random password
        $password = [System.Web.Security.Membership]::GeneratePassword(12, 2)

        # Output the username and password to a text file
        $username = "$firstName$lastName"
        
        if (-not [string]::IsNullOrWhiteSpace($middleInitial)) {
            $username = "$firstName$middleInitial$lastName"
        }

        Write-Output "$username - $password" | Out-File -Append -FilePath "C:\Path\To\Your\File.txt"  # Change the file path as needed

        # Construct the display name
        if (-not [string]::IsNullOrWhiteSpace($middleInitial)) {
            $displayName = "$lastName, $firstName $middleInitial"
        } else {
            $displayName = "$lastName, $firstName"
        }

        # Determine username prefix based on OU
        $ouName = ($ouDistinguishedName -split ',')[0] -replace '^OU='

        switch ($ouName) {
            "Domain Admins" { $username = "da-$username" }
            "Server Users" { $username = "su-$username" }
            "Service Accounts" { $username = "svc-$username" }
            "Workstation Admins" { $username = "wsadm-$username" }
            "Contractor" { $username = "$username" }
            "Full Time Employee" { $username = "$username" }
            "Vendor" { $username = "$username" }
            default { $username = "$username" }  # No prefix for unknown OUs
        }

        # Create the new AD user
        New-ADUser -Name $displayName -GivenName $firstName -Surname $lastName -SamAccountName $username `
                   -UserPrincipalName "$username@$domain" -Path $ouDistinguishedName `
                   -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) `
                   -Enabled $true -PasswordNeverExpires $false -ChangePasswordAtLogon $true

        Write-Host "User $displayName created successfully with username: $username"
    }
}

# Function to unlock an Active Directory user account
function Unlock-ADUserAccount {
    $username = Read-Host "Enter the username of the account to unlock"
    if (-not $username) { Show-MainMenu }

    Unlock-ADAccount -Identity $username
    Write-Host "Account $username has been unlocked successfully."
}

# Function to reset the password of an Active Directory user account
function Reset-ADUserPassword {
    $username = Read-Host "Enter the username of the account to reset the password"
    if (-not $username) { Show-MainMenu }
    
    # Generate a random password
    $newPassword = [System.Web.Security.Membership]::GeneratePassword(12, 2)
    Write-Host "Generated new random password: $newPassword"

    Set-ADAccountPassword -Identity $username -NewPassword (ConvertTo-SecureString $newPassword -AsPlainText -Force) -Reset
    Write-Output "$username - $newPassword" | Out-File -Append -FilePath "C:\Path\To\Your\File.txt"  # Change the file path as needed
    Write-Host "Password for account $username has been reset successfully."
}

# Main menu for account management
function Show-MainMenu {
    Write-Host "Select an option:"
    Write-Host "1. Create New AD User"
    Write-Host "2. Unlock AD User Account"
    Write-Host "3. Reset AD User Password"
    Write-Host "4. Toggle Group Membership"
    $selection = Read-Host "Enter your choice"
    
    if (-not $selection) { Show-MainMenu }

    switch ($selection) {
        "1" { Create-NewADUser }
        "2" { Unlock-ADUserAccount }
        "3" { Reset-ADUserPassword }
        "4" { Toggle-GroupMembership }
        default { Write-Host "Invalid selection. Please try again."; Show-MainMenu }
    }
}

# Start the main menu
Show-MainMenu
