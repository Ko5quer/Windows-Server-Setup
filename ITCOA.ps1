function Display_Menu1 () {
    Write-Host "1. Change timezone"
    Write-Host "2. Assign static IP address"
    Write-Host "3. Change Server name"
    Write-Host "4. Change server to automatically download updates"
    Write-Host "5. Enable remote desktop"
    Write-Host "6. Install features"
    Write-Host "7. Exit"
}
function Deliverable_1 () {
        while ($true) {
        Display_Menu1
        $choice = Read-Host "Pick an option (1-7):"

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
            Write-Host "Exiting script."
            break
        }
        else {
            Write-Host "Invalid choice, please try again.`n"
        }
    }

}
function Display_Menu2 () {
    Write-Host "1. Promte to domain controller and create a new forest "
    Write-Host "2. Create Organisational units and user account"
    Write-Host "3. Exit"
}
function OUStructure (){
    $domain = "DC=Traction,DC=local"

    if (-not (Get-ADOrganizationalUnit -Filter 'Name -eq "Employee"' -SearchBase $domain -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name "Employee" -Path $domain
        Write-Host "Created OU=Employee"
    }

    $departments = @("IT", "HR", "Sales", "Engineering")

    foreach ($dept in $departments) {
        $ouPath = "OU=Employee,$domain"
        if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$dept'" -SearchBase $ouPath -ErrorAction SilentlyContinue)) {
            New-ADOrganizationalUnit -Name $dept -Path $ouPath
            Write-Host "Created OU=$dept under Employee"
        }
        $computersOU = "OU=Computers,OU=$dept,OU=Employee,$domain"
        if (-not (Get-ADOrganizationalUnit -Filter 'Name -eq "Computers"' -SearchBase "OU=$dept,OU=Employee,$domain" -ErrorAction SilentlyContinue)) {
            New-ADOrganizationalUnit -Name "Computers" -Path "OU=$dept,OU=Employee,$domain"
            Write-Host "Created OU=Computers under OU=$dept"
        }

              if (-not (Get-ADOrganizationalUnit -Filter 'Name -eq "Users"' -SearchBase "OU=$dept,OU=Employee,$domain" -ErrorAction SilentlyContinue)) {
            New-ADOrganizationalUnit -Name "Users" -Path "OU=$dept,OU=Employee,$domain"
            Write-Host "Created OU=Users under OU=$dept"
        }
    }
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
                -SafeModeAdministratorPassword (ConvertTo-SecureString "YourSafeModePassword" -AsPlainText -Force) `
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
            Write-Host "Exiting Deliverable_2 menu."
            break
        } 
        else {
            Write-Host "Invalid choice, please try again.`n"
        }
    }
}




function Display_Menu3 (){
    Write-Host "1.Configure DNS"
    Write-Host "2.Configure DCP"
}

function Deliverable_3 () {
    while($true){
        Display_Menu3
        $choice=Read-Host "Pick an option:"
        if($choice -eq '1'){
            Install-WindowsFeature -Name DNS -IncludeManagementTools
            Add-DnsServerPrimaryZone -Name "traction.local"
                -Zonefile "traction.local.dns" `
                -DynamicUpdate Secure 
            Add-DnsServerPrimaryZone -NetworkId "192.168.1.0/24"
            -ZoneFile "1.168.192.in-addr.arpa.dns" 
            -DynamicUpdate Secure

            #Add records for server and computers
            Add-DnsServerResourceRecordA -Name "TRACTION-SRV01" 
                -ZoneName "traction.local" 
                -IPv4Address "192.168.1.10"
            Add-DnsServerResourceRecordA -Name "Amanuel-PC" 
                -ZoneName "traction.local" 
                -IPv4Address "192.168.1.105"
        }elseif ($choice -eq '2'){
            Install-WindowsFeature -Name DHCP -IncludeManagementTools
            Add-DhcpServerv4Scope -Name "TractionScope"` 
                -StartRange 192.168.1.100 `
                -EndRange 192.168.1.200 `
                -SubnetMask 255.255.255.0 `
                -State Active
            Set-DhcpServerv4OptionValue -ScopeId 192.168.1.0 `
                -Router 192.168.1.1 `
                -DnsServer 192.168.1.10 `
                -DnsDomain "traction.local"

            Add-DhcpServerInDc -DnsName "TRACTION-SRV01.traction.local" 
                -IpAddress 192.168.1.10 
            Add-DhcpServer4Reservation ` 
                -ScopeId 192.168.1.0 `
                -IPAddress 192.168.1.105 `
                 -ClientId "00-11-22-33-44-55" `
                 -Description "Alex Manuel Workstation" 
        }elseif ($choice -eq '3'){
            Write-Host "Exiting Deliverable 3 Menu"
            break
        }else {
            Write-Host "Invalid input "
        }
    }
}

function Display_Menu4(){
    Write-Host "1.Create GPO for Sales"
    Write-Host "2.Create GPO for Engineering Policy"
    Write-Host "3.Create a GPO for all users"
    Write-Host "4. Create a GPO Domain password policy "
}

function Deliverable_4 () {

}