$users = @(
    @("Rithabile", "Pitsi", "IT", "uptstri"),
    @("Alice", "Zifunzi", "HR", "uzifuali"),
    @("Mike", "Johnson", "Sales", "ujohnmi"),
    @("Alex", "Manuel", "Engineering", "umanual"),
    @("Jonathen", "Aljore", "Engineering", "ualijojo")
)

# Loop through the array using index
for ($i = 0; $i -lt $users.Length; $i++) {
    $user = $users[$i]
    New-ADUser -Name "$($user[0]) $($user[1])" `
        -GivenName $user[0] `
        -Surname $user[1] `
        -SamAccountName $user[3] `
        -UserPrincipalName "$($user[3])@Traction.local" `
        -Path "OU=Users, OU=$($user[2]), OU=Employee,DC=Traction,DC=local" `
        -AccountPassword (ConvertTo-SecureString "Saviour1@" -AsPlainText -Force) `
        -Enabled $true
    if ($user[2] -eq "Engineering") {
        New-ADComputer -Name "$($user[2])-$i" `
            -Path "OU=Computers, OU=$($user[2]), OU=Employee,DC=Traction,DC=local" `
            -Enabled $true
    } elseif ($user[2] -eq "Sales") {
        New-ADComputer -Name "$($user[2])-$i" `
            -Path "OU=Computers, OU=$($user[2]), OU=Employee,DC=Traction,DC=local" `
            -Enabled $true
    } elseif ($user[2] -eq "HR") {
        New-ADComputer -Name "$($user[2])-$i" `
            -Path "OU=Computers, OU=$($user[2]), OU=Employee,DC=Traction,DC=local" `
            -Enabled $true
    } elseif ($user[2] -eq "IT") {
        New-ADComputer -Name "$($user[2])-$i" `
            -Path "OU=Computers, OU=$($user[2]), OU=Employee,DC=Traction,DC=local" `
            -Enabled $true
    } else {
        Write-Output "Error: Unknown OU for $($user[3])"
    }
}
  




New-ADComputer -Name "" `
    -Path "OU= ,DC=Traction,DC=local" `
    -Enabled $true