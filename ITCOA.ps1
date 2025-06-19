# Function to display the setup menu for Deliverable 1
function Display_Menu1 () {
    Write-Host "Deliverable 1"
    Write-Host "1. Change timezone"
    Write-Host "2. Assign static IP address"
    Write-Host "3. Change Server name"
    Write-Host "4. Change server to automatically download updates"
    Write-Host "5. Enable remote desktop"
    Write-Host "6. Install features"
    Write-Host "7. Proof"
    Write-Host "8. Exit"
}

# Main function for server configuration tasks
function Deliverable_1 () {
    while ($true) {
        # Show the menu and get user input
        Display_Menu1
        $choice = Read-Host "Pick an option (1-8):"

        if ($choice -eq '1') {
            # Change timezone to South Africa Standard Time
            Set-TimeZone -Id "South Africa Standard Time"
            Write-Host "Timezone changed to South Africa Standard Time.`n"

        } elseif ($choice -eq '2') {
            # Assign a static IP address to Ethernet adapter
            New-NetIPAddress -InterfaceAlias "Ethernet" `
                -IPAddress "192.168.1.10" `
                -PrefixLength 24
            Write-Host "Static IP assigned to 192.168.1.10.`n"

        } elseif ($choice -eq '3') {
            # Rename the server
            Rename-Computer -NewName "TRACTION-SVR01" -Force -PassThru
            Write-Host "Server renamed to TRACTION-SVR01.`n"

        } elseif ($choice -eq '4') {
            # Enable automatic Windows updates via registry
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
                -Name AUOptions -Value 4
            Write-Host "Windows Update set to automatically download and install updates.`n"

        } elseif ($choice -eq '5') {
            # Enable Remote Desktop and open firewall rule
            Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
            Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
            Write-Host "Remote Desktop enabled.`n"

        } elseif ($choice -eq '6') {
            # Install commonly used Windows Server features
            Install-WindowsFeature -Name DNS -IncludeManagementTools
            Install-WindowsFeature -Name DHCP -IncludeManagementTools
            Install-WindowsFeature -Name FS-FileServer
            Install-WindowsFeature -Name GPMC
            Install-WindowsFeature -Name Web-Server -IncludeManagementTools
            Write-Host "Features installed.`n"

        } elseif ($choice -eq '7') {
            # Display proof of system settings and installed features
            Get-TimeZone
            ipconfig /all
            hostname
            Get-WindowsFeature DNS, DHCP, FS-FileServer, GPMC, Web-Server

        } elseif ($choice -eq '8') {
            # Exit the script loop
            Write-Host "Exiting script."
            break

        } else {
            # Handle invalid input
            Write-Host "Invalid choice, please try again.`n"
        }
    }
}


# Function to display the menu for Deliverable 2
function Display_Menu2 () {
    Write-Host "Deliverable 2"
    Write-Host "1. Promote to domain controller and create a new forest"
    Write-Host "2. Create Organizational Units and user accounts"
    Write-Host "3. Proof"
    Write-Host "4. Exit"
}

# Main function to execute chosen tasks
function Deliverable_2 () {
    # Assuming OUStructure is a separate function that creates the required OU hierarchy
    OUStructure 

    while ($true) {
        # Display the menu and get user input
        Display_Menu2
        $choice = Read-Host "Pick an option (1-3):"

        if ($choice -eq '1') {
            # ------------------------
            # Option 1: Promote server to Domain Controller
            # ------------------------

            # Install Active Directory Domain Services (AD DS) role
            Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
            
            # Import the ADDS deployment module to access Install-ADDSForest
            Import-Module ADDSDeployment

            # Promote the server to a domain controller and create a new forest "Traction.local"
            Install-ADDSForest `
                -DomainName "Traction.local" `
                -CreateDnsDelegation:$false `
                -DatabasePath "C:\Windows\NTDS" `
                -LogPath "C:\Windows\NTDS" `
                -SysvolPath "C:\Windows\SYSVOL" `
                -InstallDns:$true `
                -SafeModeAdministratorPassword (ConvertTo-SecureString "Password1@" -AsPlainText -Force) `
                -Force:$true

            # Notify user and exit loop since reboot is required
            Write-Host "Domain controller promotion initiated. Server will reboot automatically."
            break
        } 
        
        elseif ($choice -eq '2') {
            # ------------------------
            # Option 2: Create OUs and user accounts
            # ------------------------

            # Define user accounts to be created: FirstName, LastName, Department, Username
            $users = @(
                @("Rithabile", "Pitsi", "IT", "uptstri"),
                @("Alice", "Zifunzi", "HR", "uzifuali"),
                @("Mike", "Johnson", "Sales", "ujohnmi"),
                @("Alex", "Manuel", "Engineering", "umanual"),
                @("Jonathen", "Allen", "Engineering", "uallenjo")
            )

            foreach ($user in $users) {
                $firstName = $user[0]
                $lastName = $user[1]
                $department = $user[2]
                $username = $user[3]
                # Build OU path based on department
                $ouPath = "OU=Users,OU=$department,OU=Employee,DC=Traction,DC=local"
                # Set a secure password for the user
                $password = ConvertTo-SecureString "Password1@" -AsPlainText -Force

                # Only create user if they don't already exist
                if (-not (Get-ADUser -Filter {SamAccountName -eq $username} -ErrorAction SilentlyContinue)) {
                    New-ADUser `
                        -Name "$firstName $lastName" `
                        -GivenName $firstName `
                        -Surname $lastName `
                        -SamAccountName $username `
                        -UserPrincipalName "$username@Traction.local" `
                        -AccountPassword $password `
                        -Path $ouPath `
                        -Enabled $true
                    Write-Host "Created user: $firstName $lastName in OU=$department"
                } else {
                    Write-Host "User $username already exists."
                }
            }
        } 
        
        elseif ($choice -eq '3') {
            # ------------------------
            # Option 3: Proof of domain setup
            # ------------------------

            # Display domain information
            Get-ADDomain 

            # Display forest information
            Get-ADForest

            # Display all Organizational Units
            Get-ADOrganizationalUnit -Filter *

        } 
        
        elseif ($choice -eq '4') {
            # Exit the menu loop
            Write-Host "Exiting Deliverable_2 menu."   
            break
        } 
        else {
            # Handle invalid input
            Write-Host "Invalid choice, please try again.`n"
            break
        }
    }
}


# Function to display the menu options for Deliverable 3
function Display_Menu3 (){
    Write-Host "Deliverable 3"
    Write-Host "1. Configure DNS"
    Write-Host "2. Configure DHCP"
    Write-Host "3. Exit"
}

# Main function that handles DNS and DHCP configuration
function Deliverable_3(){
    while ($true){
        # Prompt user for input
        $choice = Read-Host "Pick an option 1-3"

        if ($choice -eq '1') {
            # ---------------------------
            # Option 1: Configure DNS
            # ---------------------------

            # Install the DNS Server role and management tools
            Install-WindowsFeature -Name DNS -IncludeManagementTools

            # Create a forward lookup zone if it doesn't exist
            if (-not (Get-DnsServerZone -Name "traction.local" -ErrorAction SilentlyContinue)) {
                Add-DnsServerPrimaryZone `
                    -Name "traction.local" `
                    -ZoneFile "traction.local.dns" `
                    -DynamicUpdate Secure `
                    -ReplicationScope "Forest"
            }

            # Create a reverse lookup zone if it doesn't exist
            if (-not (Get-DnsServerZone -Name "1.168.192.in-addr.arpa" -ErrorAction SilentlyContinue)) {
                Add-DnsServerPrimaryZone `
                    -NetworkId "192.168.1.0/24" `
                    -ZoneFile "1.168.192.in-addr.arpa.dns" `
                    -DynamicUpdate Secure `
                    -ReplicationScope "Forest"
            }

            # Add A (Host) records to the DNS zone
            Add-DnsServerResourceRecordA `
                -Name "TRACTION-SRV01" `
                -ZoneName "traction.local" `
                -IPv4Address "192.168.1.10"

            Add-DnsServerResourceRecordA `
                -Name "Amanuel-PC" `
                -ZoneName "traction.local" `
                -IPv4Address "192.168.1.105"

        } elseif ($choice -eq '2') {
            # ---------------------------
            # Option 2: Configure DHCP
            # ---------------------------

            # Install the DHCP Server role and management tools
            Install-WindowsFeature -Name DHCP -IncludeManagementTools

            # Create a DHCP scope with IP range 192.168.1.100 - 192.168.1.200
            Add-DhcpServerv4Scope -Name "Main Scope" -StartRange 192.168.1.100 -EndRange 192.168.1.200 -SubnetMask 255.255.255.0

            # Configure DHCP options for the scope:
            # Default gateway (Router)
            Set-DhcpServerv4OptionValue -ScopeId 192.168.1.0 -Router 192.168.1.1

            # DNS server IP address
            Set-DhcpServerv4OptionValue -ScopeId 192.168.1.0 -DnsServer 192.168.1.10

            # DNS domain name
            Set-DhcpServerv4OptionValue -ScopeId 192.168.1.0 -DnsDomain "Traction.local"

            # Authorize the DHCP server in Active Directory
            Add-DhcpServerInDC -DnsName "TRACTION-SRV01.Traction.local" -IPAddress 192.168.1.10

            # Reserve a specific IP address for a device (e.g., Alex Manuel's PC)
            Add-DhcpServerv4Reservation -ScopeId 192.168.1.0 `
                -IPAddress 192.168.1.105 `
                -ClientId "00-11-22-33-44-55" `
                -Description "Alex Manuel PC"

        } elseif ($choice -eq '3') {
            # Exit the loop and script
            Write-Host "Exiting"
            break
        } else {
            # Handle invalid input
            Write-Host "Invalid choice. Please choose 1 for DNS or 2 for DHCP."
        }
    }
}

# Display the menu options for Deliverable 4
function Display_Menu4(){
    Write-Host "Deliverable 4"
    Write-Host "1. Create GPO for Sales"
    Write-Host "2. Create GPO for Engineering Policy"
    Write-Host "3. Create a GPO for All Users"
    Write-Host "4. Create a GPO Domain Password Policy"
    Write-Host "5. Proof"
    Write-Host "6. Exit"
}

# Main logic to run selected GPO configuration tasks
function Deliverable_4 () {
    while ($true) {
        # Show the menu
        Display_Menu4
        $choice = Read-Host "Enter your choice"

        if ($choice -eq "1") {
            # --- Option 1: Create and configure GPO for Sales department ---

            # Create shared folder for Sales documents
            New-Item -Path "C:\Shares\SalesDocs" -ItemType Directory

            $gpoName = "Sales Policy"
            
            # Create the GPO only if it doesn't already exist
            if (-not (Get-GPO -Name $gpoName -ErrorAction SilentlyContinue)) {
                New-GPO -Name $gpoName

                # Link GPO to the Sales OU
                New-GPLink -Name $gpoName -Target "OU=Sales,OU=Employee,DC=Traction,DC=local"
                
                # Disable USB storage by setting Start=4 in USBSTOR service
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR" -ValueName "Start" -Type DWord -Value 4
                
                # Map S: drive to shared SalesDocs folder
                New-GPPrefDriveMap -Name $gpoName -Action Create -Location "\\TRACTION-SVR01\SalesDocs" -DriveLetter "S" -UseLetter -UserContext
                
                # Share the folder with full access to Sales group
                New-SmbShare -Name "SalesDocs" -Path "C:\Shares\SalesDocs" -FullAccess "Traction\Sales"

                Write-Host "Sales GPO created and configured."
            } else {
                Write-Host "GPO '$gpoName' already exists."
            }

        } elseif ($choice -eq "2") {
            # --- Option 2: Create and configure GPO for Engineering department ---
            $gpoName = "Engineering Policy"
            
            if (-not (Get-GPO -Name $gpoName -ErrorAction SilentlyContinue)) {
                New-GPO -Name $gpoName
                New-GPLink -Name $gpoName -Target "OU=Engineering,OU=Employee,DC=Traction,DC=local"
                
                # Enable Remote Desktop (0 = enabled)
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" -ValueName "fDenyTSConnections" -Type DWord -Value 0
                
                # Allow use of Command Prompt (0 = allowed)
                Set-GPRegistryValue -Name $gpoName -Key "HKCU\Software\Policies\Microsoft\Windows\System" -ValueName "DisableCMD" -Type DWord -Value 0
                
                Write-Host "Engineering GPO created and configured."
            } else {
                Write-Host "GPO '$gpoName' already exists."
            }

        } elseif ($choice -eq "3") {
            # --- Option 3: Create and configure GPO for all users ---
            $gpoName = "All Users Policy"

            if (-not (Get-GPO -Name $gpoName -ErrorAction SilentlyContinue)) {
                New-GPO -Name $gpoName
                New-GPLink -Name $gpoName -Target "OU=Employee,DC=Traction,DC=local"

                # Disable access to Control Panel
                Set-GPRegistryValue -Name $gpoName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoControlPanel" -Type DWord -Value 1

                # Redirect Documents folder to server location
                Set-GPFolderRedirection -Name $gpoName -Folder Documents -RedirectTo Basic -TargetPath "\\TRACTION-SVR01\user\%USERNAME%"

                # Set a corporate wallpaper for desktops
                Set-GPRegistryValue -Name $gpoName -Key "HKCU\Control Panel\Desktop" -ValueName "Wallpaper" -Type String -Value "\\TRACTION-SVR01\Wallpapers\corp_wallpaper.jpg"

                Write-Host "All Users GPO created and configured."
            } else {
                Write-Host "GPO '$gpoName' already exists."
            }

        } elseif ($choice -eq "4") {
            # --- Option 4: Create and configure domain-wide password policy ---
            $gpoName = "Domain Password Policy"

            if (-not (Get-GPO -Name $gpoName -ErrorAction SilentlyContinue)) {
                New-GPO -Name $gpoName
                New-GPLink -Name $gpoName -Target "DC=Traction,DC=local"

                # Password must be changed every 90 days
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -ValueName "MaximumPasswordAge" -Type DWord -Value 90

                # Password must be kept at least 1 day before changing
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -ValueName "MinimumPasswordAge" -Type DWord -Value 1

                # Minimum password length of 8 characters
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -ValueName "MinimumPasswordLength" -Type DWord -Value 8

                # Prevent reuse of last 5 passwords
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -ValueName "PasswordHistorySize" -Type DWord -Value 5

                # Require complex passwords (e.g., uppercase, lowercase, symbols)
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "PasswordComplexity" -Type DWord -Value 1

                Write-Host "Password Policy GPO created and configured."
            } else {
                Write-Host "GPO '$gpoName' already exists."
            }

        } elseif ($choice -eq "5") {
            # --- Option 5: Display proof of configurations ---
            
            # Display status of DNS and DHCP features
            Get-WindowsFeature DNS 
            Get-WindowsFeature DHCP

            # Show configured DNS zones
            Get-DnsServerZone

            # Show existing DHCP scopes and reservations
            Get-DhcpServerv4Scope
            Get-DhcpServerv4Reservation -ScopeId 192.168.1.0

        } elseif ($choice -eq "6") {
            # Exit the script
            Write-Host "Exiting GPO menu."
            break
        } else {
            # Handle invalid input
            Write-Host "Invalid option. Please choose between 1 and 6.`n"
        }
    }
}




# This function is intended to configure a client machine to connect to the domain.
function client (){
    # IP address of the domain controller
    $serverIP = "192.168.1.10"                     

    # Fully Qualified Domain Name (FQDN) of the domain
    $domainName = "Traction.local"

    # Domain username (note the double backslash for escaping in PowerShell)
    $domainUser = "Traction\\uptstri"       

    # Plain text domain password (Note: storing plain text passwords is not secure)
    $domainPassword = "Password1@"                 

    # Set the DNS server for the network interface to point to the domain controller
    Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses $serverIP

    # Convert the plain text password to a secure string
    $secPassword = ConvertTo-SecureString $domainPassword -AsPlainText -Force

    # Create a credential object with the domain user and secure password
    $cred = New-Object System.Management.Automation.PSCredential ($domainUser, $secPassword)
}


# This function configures firewall rules and hardens security on the Windows Server.
function Deliverable_5 {
    Write-Host "`n--- Deliverable 6: Windows Server Hardening and Security ---`n"

    # Enable Windows Firewall for Domain, Public, and Private profiles
    Write-Host "Enabling Windows Firewall for all profiles..."
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

    # OPTIONAL: Clear all existing inbound rules (commented out because it's risky in production)
    # Get-NetFirewallRule -Direction Inbound | Remove-NetFirewallRule

    # Allow Remote Desktop Protocol (RDP) on TCP port 3389
    Write-Host "Creating rule to allow RDP..."
    New-NetFirewallRule -DisplayName "Allow RDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow

    # Allow DNS on UDP port 53
    Write-Host "Creating rule to allow DNS..."
    New-NetFirewallRule -DisplayName "Allow DNS (UDP)" -Direction Inbound -Protocol UDP -LocalPort 53 -Action Allow

    # Allow DNS on TCP port 53
    New-NetFirewallRule -DisplayName "Allow DNS (TCP)" -Direction Inbound -Protocol TCP -LocalPort 53 -Action Allow

    # Allow DHCP server communication on UDP port 67
    Write-Host "Creating rule to allow DHCP Server..."
    New-NetFirewallRule -DisplayName "Allow DHCP (UDP)" -Direction Inbound -Protocol UDP -LocalPort 67 -Action Allow

    # Allow web traffic: HTTP on port 80
    # and HTTPS on port 443
    Write-Host "Creating rules to allow HTTP and HTTPS..."
    New-NetFirewallRule -DisplayName "Allow HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow
    New-NetFirewallRule -DisplayName "Allow HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow

    Write-Host "`nWindows Firewall has been configured on TRACTION-SRV01 to allow only essential services."
}


while ($true){
Write-Host "1. Deliverable_1"
Write-Host "2. Deliverable_2"
Write-Host "3. Deliverable_3"
Write-Host "4. Deliverable_4"
Write-Host "5. Deliverable_5"
Write-Host "6. Client Side options"
$choice= Read-Host "Pick an option"
if ($choice -eq '1'){
    Deliverable_1
} elseif ($choice -eq '2'){
    Deliverable_2
} elseif ($choice -eq '3'){
    Deliverable_3
}elseif ($choice -eq '4'){
    Deliverable_4
}elseif ($choice -eq '5'){
    Deliverable_5
}elseif ($choice -eq '6'){
	client
}else {
Write-Host "Invalid"
}
}