# Variables
$domainName = "yourdomain"
$topLevelDomain = "com"
$ouPath = "OU=Accounts,DC=$domainName,DC=$topLevelDomain"
$groupOuPath = "OU=Groups,DC=$domainName,DC=$topLevelDomain"
$outfilePath = "C:\Path\To\PasswordFile.txt"

# Function to generate a random password
function Generate-RandomPassword {
    $length = 12
    $possibleChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
    $password = ""

    for ($i = 0; $i -lt $length; $i++) {
        $randomIndex = Get-Random -Minimum 0 -Maximum $possibleChars.Length
        $password += $possibleChars[$randomIndex]
    }

    return $password
}

# Function to get sub-OUs under the "Accounts" OU but exclude "Accounts" and "Employees" OUs
function Get-SubOUsInAccountsOU {
    $subOUs = Get-ADOrganizationalUnit -Filter * -SearchBase $ouPath | Where-Object {
        $_.DistinguishedName -ne "OU=Accounts,DC=$domainName,DC=$topLevelDomain" -and
        $_.DistinguishedName -ne "OU=Employees,OU=Accounts,DC=$domainName,DC=$topLevelDomain"
    }
    return $subOUs
}

# Function to get groups from the Groups OU and its sub-OUs
function Get-GroupsInGroupsOU {
    $groups = Get-ADGroup -Filter * -SearchBase $groupOuPath
    return $groups
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
        $password = Generate-RandomPassword

        # Output the service name and password to a text file
        $username = "svc-$serviceName"
        Write-Output "$username - $password" | Out-File -Append -FilePath $outfilePath

        # Create the new Service Account user
        New-ADUser -Name $serviceName -SamAccountName $username `
                   -UserPrincipalName "$username@$domainName.$topLevelDomain" -Path $ouDistinguishedName `
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
        $password = Generate-RandomPassword

        # Construct the display name
        if (-not [string]::IsNullOrWhiteSpace($middleInitial)) {
            $displayName = "$lastName, $firstName $middleInitial"
            $username = "$firstName$middleInitial$lastName"
        } else {
            $displayName = "$lastName, $firstName"
            $username = "$firstName$lastName"
        }

        # Output the username and password to a text file
        Write-Output "$username - $password" | Out-File -Append -FilePath $outfilePath

        # Determine username prefix based on OU
        $ouName = ($ouDistinguishedName -split ',')[0] -replace '^OU='

        switch ($ouName) {
            "Domain Admins" { $username = "da-$username" }
            "Server Users" { $username = "su-$username" }
            "Service Accounts" { $username = "svc-$username" }
            "Workstation Admins" { $username = "wsadm-$username" }
        }

        # Create the new AD user
        New-ADUser -Name $displayName -GivenName $firstName -Surname $lastName -SamAccountName $username `
                   -UserPrincipalName "$username@$domainName.$topLevelDomain" -Path $ouDistinguishedName `
                   -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) `
                   -Enabled $true -PasswordNeverExpires $false -ChangePasswordAtLogon $true

        Write-Host "User $displayName created successfully with username: $username"
    }
}

# Function to reset a user’s password
function Reset-ADUserPassword {
    $username = Read-Host "Enter the username to reset the password for"
    $user = Get-ADUser -Identity $username

    if ($user) {
        $newPassword = Generate-RandomPassword
        Set-ADAccountPassword -Identity $user -NewPassword (ConvertTo-SecureString $newPassword -AsPlainText -Force)
        Write-Output "$username - $newPassword" | Out-File -Append -FilePath $outfilePath
        Write-Host "Password for $username has been reset. New password: $newPassword"
    } else {
        Write-Host "User not found!"
    }
}

# Function to unlock a user’s account
function Unlock-ADUserAccount {
    $username = Read-Host "Enter the username to unlock"
    Unlock-ADAccount -Identity $username
    Write-Host "User $username has been unlocked."
}

# Function to toggle group membership
function Toggle-GroupMembership {
    $username = Read-Host "Enter the username to manage group membership"
    $user = Get-ADUser -Identity $username
    if ($user) {
        $groupName = Show-GroupMenu
        if ($groupName) {
            $group = Get-ADGroup -Filter { Name -eq $groupName }

            if ($group) {
                $isMember = Get-ADGroupMember -Identity $group | Where-Object { $_.SamAccountName -eq $username }
                if ($isMember) {
                    Remove-ADGroupMember -Identity $group -Members $user -Confirm:$false
                    Write-Host "$username removed from $groupName."
                } else {
                    Add-ADGroupMember -Identity $group -Members $user -Confirm:$false
                    Write-Host "$username added to $groupName."
                }
            } else {
                Write-Host "Group $groupName not found!"
            }
        } else {
            Show-MainMenu
        }
    } else {
        Write-Host "User $username not found!"
    }
}

# Function to display the main menu
function Show-MainMenu {
    Clear-Host
    Write-Host "1. Create New AD User"
    Write-Host "2. Reset User Password"
    Write-Host "3. Unlock User Account"
    Write-Host "4. Toggle Group Membership"
    Write-Host "5. Exit"
    
    $choice = Read-Host "Select an option"
    
    switch ($choice) {
        1 { Create-NewADUser }
        2 { Reset-ADUserPassword }
        3 { Unlock-ADUserAccount }
        4 { Toggle-GroupMembership }
        5 { Exit }
        default { Show-MainMenu }
    }
}

# Function to show the OU selection menu
function Show-OUMenu {
    $ous = Get-SubOUsInAccountsOU
    $i = 1
    foreach ($ou in $ous) {
        Write-Host "$i. $($ou.Name)"
        $i++
    }

    $choice = Read-Host "Select the OU by number"
    if ($choice -match '^\d+$' -and $choice -ge 1 -and $choice -le $ous.Count) {
        return $ous[$choice - 1].DistinguishedName
    } else {
        Show-MainMenu
    }
}

# Function to show the group selection menu from Groups OU and sub-OUs
function Show-GroupMenu {
    $groups = Get-GroupsInGroupsOU
    $i = 1
    foreach ($group in $groups) {
        Write-Host "$i. $($group.Name)"
        $i++
    }

    $choice = Read-Host "Select the Group by number"
    if ($choice -match '^\d+$' -and $choice -ge 1 -and $choice -le $groups.Count) {
        return $groups[$choice - 1].Name
    } else {
        return $null
    }
}

# Start the script
Show-MainMenu
