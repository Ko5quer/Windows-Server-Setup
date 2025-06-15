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
function Deliverable_1 () {
        while ($true) {
        Display_Menu1
        $choice = Read-Host "Pick an option (1-8):"

        if ($choice -eq '1') {
            Set-TimeZone -Id "South Africa Standard Time"
            Write-Host "Timezone changed to South Africa Standard Time.`n"
        } 
        elseif ($choice -eq '2') {
            New-NetIPAddress -InterfaceAlias "Ethernet" `
                -IPAddress "192.168.1.10" `
                -PrefixLength 24
            Write-Host "Static IP assigned to 192.168.1.10.`n"
        } 
        elseif ($choice -eq '3') {
            Rename-Computer -NewName "TRACTION-SVR01" -Force -PassThru
            Write-Host "Server renamed to TRACTION-SVR01.`n"
        } 
        elseif ($choice -eq '4') {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
                -Name AUOptions -Value 4
            Write-Host "Windows Update set to automatically download and install updates.`n"
        } 
        elseif ($choice -eq '5') {
            Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
            Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
            Write-Host "Remote Desktop enabled.`n"
        } 
        elseif ($choice -eq '6') {
            Install-WindowsFeature -Name DNS -IncludeManagementTools
            Install-WindowsFeature -Name DHCP -IncludeManagementTools
            Install-WindowsFeature -Name FS-FileServer
            Install-WindowsFeature -Name GPMC
            Install-WindowsFeature -Name Web-Server -IncludeManagementTools
            Write-Host "Features installed.`n"
        } 
        elseif ($choice -eq '7') {
            Get-TimeZone
            ipconfig /all
            hostname
            Get-WindowsFeature DNS, DHCP, FS-FileServer, GPMC, Web-Server
        } elseif ($choice -eq '8'){
            Write-Host "Exiting script."
            break
        }
        else {
            Write-Host "Invalid choice, please try again.`n"
        }
    }

}

function OUStructure () {
    $domain = "DC=Traction,DC=local"
    $employeeOU = $null
    try {
        $employeeOU = Get-ADOrganizationalUnit -Filter 'Name -eq "Employee"' -SearchBase $domain -ErrorAction Stop
    } catch {
        # Do nothing
    }

    if (-not $employeeOU) {
        New-ADOrganizationalUnit -Name "Employee" -Path $domain
        Write-Host "Created OU=Employee"
    }

    $departments = @("IT", "HR", "Sales", "Engineering")

    foreach ($dept in $departments) {
        $ouPath = "OU=Employee,$domain"
        $deptOU = $null
        try {
            $deptOU = Get-ADOrganizationalUnit -Filter "Name -eq '$dept'" -SearchBase $ouPath -ErrorAction Stop
        } catch {
            # Do nothing
        }

        if (-not $deptOU) {
            New-ADOrganizationalUnit -Name $dept -Path $ouPath
            Write-Host "Created OU=$dept under Employee"
        }

        $computersOU = $null
        try {
            $computersOU = Get-ADOrganizationalUnit -Filter 'Name -eq "Computers"' -SearchBase "OU=$dept,OU=Employee,$domain" -ErrorAction Stop
        } catch {
            # Do nothing
        }

        if (-not $computersOU) {
            New-ADOrganizationalUnit -Name "Computers" -Path "OU=$dept,OU=Employee,$domain"
            Write-Host "Created OU=Computers under OU=$dept"
        }

        $usersOU = $null
        try {
            $usersOU = Get-ADOrganizationalUnit -Filter 'Name -eq "Users"' -SearchBase "OU=$dept,OU=Employee,$domain" -ErrorAction Stop
        } catch {
            #Do nothing
        }
        if (-not $usersOU) {
            New-ADOrganizationalUnit -Name "Users" -Path "OU=$dept,OU=Employee,$domain"
            Write-Host "Created OU=Users under OU=$dept"
        }
    }
}

function Display_Menu2 () {
    Write-Host "Deliverable 4"
    Write-Host "1. Promte to domain controller and create a new forest "
    Write-Host "2. Create Organisational units and user account"
    Write-Host "3. Proof"
    Write-Host "4. Exit"
}
function Deliverable_2 () {
    OUStructure
    while ($true) {
        Display_Menu2
        $choice = Read-Host "Pick an option (1-3):"

        if ($choice -eq '1') {
            Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
            
            Import-Module ADDSDeployment
            Install-ADDSForest `
                -DomainName "Traction.local" `
                -CreateDnsDelegation:$false `
                -DatabasePath "C:\Windows\NTDS" `
                -LogPath "C:\Windows\NTDS" `
                -SysvolPath "C:\Windows\SYSVOL" `
                -InstallDns:$true `
                -SafeModeAdministratorPassword (ConvertTo-SecureString "Password1@" -AsPlainText -Force) `
                -Force:$true

            Write-Host "Domain controller promotion initiated. Server will reboot automatically."
            break
        } 
        elseif ($choice -eq '2') {
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
                $ouPath = "OU=Users,OU=$department,OU=Employee,DC=Traction,DC=local"
                $password = ConvertTo-SecureString "Password1@" -AsPlainText -Force

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
            Get-ADDomain 
            Get-ADForest
            Get-ADOrganizationalUnit -Filter *

        } 
        elseif ($choice -eq '4') {
            Write-Host "Exiting Deliverable_2 menu."   
        }else {
             Write-Host "Invalid choice, please try again.`n"
            break
        }
    }
}




function Display_Menu3 (){
    Write-Host "Deliverable 3"
    Write-Host "1.Configure DNS"
    Write-Host "2.Configure DCP"
    Write-Host "3.Exit"
}
function Deliverable_3(){
    while ($true){
    $choice = Read-Host "Pick an option 1-3"

    if ($choice -eq '1') {
        Install-WindowsFeature -Name DNS -IncludeManagementTools
        if (-not (Get-DnsServerZone -Name "traction.local" -ErrorAction SilentlyContinue)) {
            Add-DnsServerPrimaryZone `
                -Name "traction.local" `
                -ZoneFile "traction.local.dns" `
                -DynamicUpdate Secure `
                -ReplicationScope "Forest"
        }
        if (-not (Get-DnsServerZone -Name "1.168.192.in-addr.arpa" -ErrorAction SilentlyContinue)) {
            Add-DnsServerPrimaryZone `
                -NetworkId "192.168.1.0/24" `
                -ZoneFile "1.168.192.in-addr.arpa.dns" `
                -DynamicUpdate Secure `
                -ReplicationScope "Forest"
        }
        Add-DnsServerResourceRecordA `
            -Name "TRACTION-SRV01" `
            -ZoneName "traction.local" `
            -IPv4Address "192.168.1.10"

        Add-DnsServerResourceRecordA `
            -Name "Amanuel-PC" `
            -ZoneName "traction.local" `
            -IPv4Address "192.168.1.105"

    } elseif ($choice -eq '2') {
        Install-WindowsFeature -Name DHCP -IncludeManagementTools
        Add-DhcpServerv4Scope -Name "Main Scope" -StartRange 192.168.1.100 -EndRange 192.168.1.200 -SubnetMask 255.255.255.0

        Set-DhcpServerv4OptionValue -ScopeId 192.168.1.0 -Router 192.168.1.1
        Set-DhcpServerv4OptionValue -ScopeId 192.168.1.0 -DnsServer 192.168.1.10
        Set-DhcpServerv4OptionValue -ScopeId 192.168.1.0 -DnsDomain "Traction.local"
        Add-DhcpServerInDC -DnsName "TRACTION-SRV01.Traction.local" -IPAddress 192.168.1.10
        Add-DhcpServerv4Reservation -ScopeId 192.168.1.0 -IPAddress 192.168.1.105 -ClientId "00-11-22-33-44-55" -Description "Alex Manuel PC"

    } elseif ($choice -eq '3') {
        Write-Host "Exiting"
    }
    else {
        Write-Host "Invalid choice. Please choose 1 for DNS or 2 for DHCP."
    }
    }
}

function Display_Menu4(){
    Write-Host "Deliverable 4"
    Write-Host "1.Create GPO for Sales"
    Write-Host "2.Create GPO for Engineering Policy"
    Write-Host "3.Create a GPO for all users"
    Write-Host "4. Create a GPO Domain password policy "
    Write-Host "5. Proof"
    Write-Host "6. Exit"
}
function Deliverable_4 () {
    while ($true) {
        Display_Menu4
        $choice = Read-Host "Enter your choice"

        if ($choice -eq "1") {
            # Sales Policy
			New-Item -Path "C:\Shares\SalesDocs" -ItemType Directory
            $gpoName = "Sales Policy"
            if (-not (Get-GPO -Name $gpoName -ErrorAction SilentlyContinue)) {
                New-GPO -Name $gpoName
                New-GPLink -Name $gpoName -Target "OU=Sales,OU=Employee,DC=Traction,DC=local"
                
                # Disable USB storage
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR" -ValueName "Start" -Type DWord -Value 4
                
                # Map shared folder
                New-GPPrefDriveMap -Name $gpoName -Action Create -Location "\\TRACTION-SVR01\SalesDocs" -DriveLetter "S" -UseLetter -UserContext
				New-SmbShare -Name "SalesDocs" -Path "C:\Shares\SalesDocs" -FullAccess "Traction\Sales"

                
                Write-Host "Sales GPO created and configured."
            } else {
                Write-Host "GPO '$gpoName' already exists."
            }

        } elseif ($choice -eq "2") {
            # Engineering Policy
            $gpoName = "Engineering Policy"
            if (-not (Get-GPO -Name $gpoName -ErrorAction SilentlyContinue)) {
                New-GPO -Name $gpoName
                New-GPLink -Name $gpoName -Target "OU=Engineering,OU=Employee,DC=Traction,DC=local"
                
                # Enable Remote Desktop
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" -ValueName "fDenyTSConnections" -Type DWord -Value 0
                
                # Allow Command Prompt
                Set-GPRegistryValue -Name $gpoName -Key "HKCU\Software\Policies\Microsoft\Windows\System" -ValueName "DisableCMD" -Type DWord -Value 0
                
                Write-Host "Engineering GPO created and configured."
            } else {
                Write-Host "GPO '$gpoName' already exists."
            }

        } elseif ($choice -eq "3") {
            # All Users Policy
            $gpoName = "All Users Policy"
            if (-not (Get-GPO -Name $gpoName -ErrorAction SilentlyContinue)) {
                New-GPO -Name $gpoName
                New-GPLink -Name $gpoName -Target "OU=Employee,DC=Traction,DC=local"
                
                # Disable Control Panel
                Set-GPRegistryValue -Name $gpoName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoControlPanel" -Type DWord -Value 1
                
                # Redirect Documents folder
                Set-GPFolderRedirection -Name $gpoName -Folder Documents -RedirectTo Basic -TargetPath "\\TRACTION-SVR01\user\%USERNAME%"
                
                # Set custom wallpaper (assuming wallpaper path is \\TRACTION-SVR01\Wallpapers\corp_wallpaper.jpg)
                Set-GPRegistryValue -Name $gpoName -Key "HKCU\Control Panel\Desktop" -ValueName "Wallpaper" -Type String -Value "\\TRACTION-SVR01\Wallpapers\corp_wallpaper.jpg"

                Write-Host "All Users GPO created and configured."
            } else {
                Write-Host "GPO '$gpoName' already exists."
            }

        } elseif ($choice -eq "4") {
            # Domain Password Policy
            $gpoName = "Domain Password Policy"
            if (-not (Get-GPO -Name $gpoName -ErrorAction SilentlyContinue)) {
                New-GPO -Name $gpoName
                New-GPLink -Name $gpoName -Target "DC=Traction,DC=local"

                # Set password policies
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -ValueName "MaximumPasswordAge" -Type DWord -Value 90
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -ValueName "MinimumPasswordAge" -Type DWord -Value 1
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -ValueName "MinimumPasswordLength" -Type DWord -Value 8
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -ValueName "PasswordHistorySize" -Type DWord -Value 5
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "PasswordComplexity" -Type DWord -Value 1

                Write-Host "Password Policy GPO created and configured."
            } else {
                Write-Host "GPO '$gpoName' already exists."
            }

        } elseif ($choice -eq "5") {
            # Check server roles and configurations
            Get-WindowsFeature DNS 
            Get-WindowsFeature DHCP

            Get-DnsServerZone
            Get-DhcpServerv4Scope
            Get-DhcpServerv4Reservation -ScopeId 192.168.1.0
        } elseif ($choice -eq "6") {
            Write-Host "Exiting GPO menu."
            break
        } else {
            Write-Host "Invalid option. Please choose between 1 and 6.`n"
        }
    }
}


function Display_Menu5(){
    Write-Host "1. Install necessary things"
    Write-Host "2. Create Certificate"
    Write-Host "3. Issue Certoficate"
    Write-Host "4. Configure Auto Enrollment"
    Write-Host "5. Proof"
    Write-Host "6. Exit"
}

function Deliverable_5 (){
    while($true){
        Display_Menu5
        $choice = Read-Host "Pick an option (1-5)"
        
        if ($choice -eq '1'){
            Install-WindowsFeature AD-Certificate -IncludeManagementTools
            Install-AdcsCertificationAuthority `
                -CAType EnterpriseRootCA `
                -CACommonName "TractionSolutionsCA" `
                -KeyLength 2048 `
                -HashAlgorithmName SHA256 `
                -CryptoProviderName "Microsoft Software Key Storage Provider"
        
        } elseif ($choice -eq '2'){
            Start-Process certreq
        
        } elseif ($choice -eq '3'){
            $inf = "[Version]`n" + `
            "Signature=`"`$Windows NT`$`"`n" + `
            "`n" + `
            "[NewRequest]`n" + `
            "Subject = `"CN=Traction.local`"`n" + `
            "KeySpec = 1`n" + `
            "KeyLength = 2048`n" + `
            "Exportable = TRUE`n" + `
            "MachineKeySet = TRUE`n" + `
            "SMIME = FALSE`n" + `
            "PrivateKeyArchive = FALSE`n" + `
            "UserProtected = FALSE`n" + `
            "UseExistingKeySet = FALSE`n" + `
            "ProviderName = `"Microsoft RSA SChannel Cryptographic Provider`"`n" + `
            "ProviderType = 12`n" + `
            "RequestType = PKCS10`n" + `
            "KeyUsage = 0xa0`n" + `
            "`n" + `
            "[EnhancedKeyUsageExtension]`n" + `
            "OID=1.3.6.1.5.5.7.3.1 ; Server Authentication`n" + `
            "`n" + `
            "[RequestAttributes]`n" + `
            "CertificateTemplate = WebServer"

            $inf | Out-File C:\TractionDomainCert.inf -Encoding ascii

            certreq -new C:\TractionDomainCert.inf C:\TractionDomainCert.req
            certreq -submit -config "TRACTION-SRV01\TractionSolutionsCA" C:\TractionDomainCert.req C:\TractionDomainCert.cer
            certreq -accept C:\TractionDomainCert.cer

        } elseif ($choice -eq '4'){
            $gpoName = "Certificate Auto-Enrollment Policy"
            New-GPO -Name $gpoName -ErrorAction SilentlyContinue
            $gpoPath = "HKLM\Software\Policies\Microsoft\Cryptography\AutoEnrollment"
            Set-GPRegistryValue -Name $gpoName -Key $gpoPath -ValueName "AEPolicy" -Type DWord -Value 7
            New-GPLink -Name $gpoName -Target "DC=Traction,DC=local"

        } elseif ($choice -eq '5'){
            Get-WindowsFeature AD-Certificate
            Get-CACert
            certuil -CAInfo
            Get-GPO -Name "Cerificate Auto-Enrollment Policy"

        } elseif ($choice -eq '6'){
            Write-Host "Exiting"
            break

        } else {
            Write-Host "Invalid input"
        }
    }
}

function client (){
    $serverIP = "192.168.1.10"                     
    $domainName = "Traction.local"
    $domainUser = "Traction\\uptstri"       
    $domainPassword = "Password1@"                 
    Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses $serverIP
    $secPassword = ConvertTo-SecureString $domainPassword -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential ($domainUser, $secPassword)
}
function Deliverable_6 {
    Write-Host "`n--- Deliverable 6: Windows Server Hardening and Security ---`n"

    # Enable Windows Firewall for all profiles
    Write-Host "Enabling Windows Firewall for all profiles..."
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

    # Clear existing inbound rules (optional but can be risky in production)
    # Get-NetFirewallRule -Direction Inbound | Remove-NetFirewallRule

    # Allow RDP (Port 3389)
    Write-Host "Creating rule to allow RDP..."
    New-NetFirewallRule -DisplayName "Allow RDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow

    # Allow DNS (Port 53 UDP & TCP)
    Write-Host "Creating rule to allow DNS..."
    New-NetFirewallRule -DisplayName "Allow DNS (UDP)" -Direction Inbound -Protocol UDP -LocalPort 53 -Action Allow
    New-NetFirewallRule -DisplayName "Allow DNS (TCP)" -Direction Inbound -Protocol TCP -LocalPort 53 -Action Allow

    # Allow DHCP (Port 67 UDP)
    Write-Host "Creating rule to allow DHCP Server..."
    New-NetFirewallRule -DisplayName "Allow DHCP (UDP)" -Direction Inbound -Protocol UDP -LocalPort 67 -Action Allow

    # Allow HTTP/HTTPS (Ports 80 and 443)
    Write-Host "Creating rules to allow HTTP and HTTPS..."
    New-NetFirewallRule -DisplayName "Allow HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow
    New-NetFirewallRule -DisplayName "Allow HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow

    Write-Host "`nWindows Firewall has been configured on TRACTION-SRV01 to allow only essential services."
}

while ($true){
Deliverable_1
Deliverable_2
Deliverable_3
Deliverable_4
Write-Host "1. Deliverable_1"
Write-Host "2. Deliverable_2"
Write-Host "3. Deliverable_3"
Write-Host "4. Deliverable_4"
Write-Host "5. Deliverable_5"
Write_Host "6. Deliverable_6"
Write-Host "7. Client Side options"
$choice= Read-Host "Pick an option"
if ($choice eq '1'){
    Deliverable_1
} elseif ($choice eq '2'){
    Deliverable_2
} elseif ($choice eq '3'){
    Deliverable_3
}elseif ($choice eq '4'){
    Deliverable_4
}elseif ($choice eq '5'){
    Deliverable_5
}elseif ($choice eq '6'){
	Deliverable_6
}elseif ($choice eq '7'{
	client
}else {
Write-Host "Invalid"
}
