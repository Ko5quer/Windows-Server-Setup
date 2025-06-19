# Windows Server Configuration and Security - README

This document outlines a complete step-by-step automation of configuring a Windows Server 2019 system using PowerShell scripts. It is structured around multiple deliverables that address server setup, domain services, DNS/DHCP configuration, group policy objects (GPOs), certificate authority setup, and hardening.

---

## Prerequisites

* Windows Server 2019
* PowerShell 5.1 or later
* Run all scripts as **Administrator**
* Ensure network connectivity where applicable

---

## Deliverable 1: Initial Server Configuration

This script prepares the server for deployment by applying essential base configurations:

* Set the timezone to South Africa Standard Time.
* Assign a static IP address (`192.168.1.10`).
* Rename the server to `TRACTION-SVR01`.
* Configure the server to automatically download and install updates.
* Enable Remote Desktop and create firewall exceptions.
* Install essential features:

  * DNS Server
  * DHCP Server
  * File Services
  * Group Policy Management Console (GPMC)
  * Web Server (IIS)
* Provide proof by showing timezone, IP config, hostname, and installed features.

---

## Deliverable 2: Promote Server to Domain Controller and Create OUs

* Install Active Directory Domain Services and promote the server to a domain controller with the forest root domain `Traction.local`.
* Automatically reboots the server after promotion.
* **OU Structure** is automatically created when the `Deliverable_2` script runs:

  * `OU=Employee`

    * `OU=IT`
    * `OU=HR`
    * `OU=Sales`
    * `OU=Engineering`

      * `OU=Computers`
      * `OU=Users`
* Create user accounts with organizational placement:

  * Rithabile Pitsi (IT)
  * Alice Zifunzi (HR)
  * Mike Johnson (Sales)
  * Alex Manuel (Engineering)
  * Jonathen Allen (Engineering)
* Proof includes domain, forest, and all OU listings.

---

## Deliverable 3: DNS and DHCP Configuration

* Install and configure DNS:

  * Primary zone: `traction.local`
  * Reverse lookup zone: `1.168.192.in-addr.arpa`
  * Add `A` records for `TRACTION-SRV01` and `Amanuel-PC`.
* Install and configure DHCP:

  * Create scope `192.168.1.100 - 192.168.1.200`
  * Configure scope options: router, DNS server, domain name.
  * Add server to AD.
  * Add reservation for Amanuel-PC.

---

## Deliverable 4: Group Policy Objects (GPOs)

Menu includes options to create:

1. **Sales Policy**

   * Disable USB storage.
   * Map shared network drive (S:).
   * Create share folder on server.

2. **Engineering Policy**

   * Enable Remote Desktop.
   * Allow Command Prompt.

3. **All Users Policy**

   * Disable Control Panel.
   * Redirect Documents folder.
   * Set custom desktop wallpaper.

4. **Domain Password Policy**

   * Enforce strong password rules (complexity, age, history, length).

5. **Proof Output**

   * Show installed DNS and DHCP features.
   * List DHCP scope and reservations.

---

## Deliverable 5: Certificate Authority and Auto-Enrollment

* Menu to:

  1. Install the AD CS role and configure an Enterprise Root CA.
  2. Launch the certificate request GUI.
  3. Generate `.inf`, submit request, and accept issued certificate.
  4. Configure auto-enrollment using GPO (`Certificate Auto-Enrollment Policy`).
  5. Output proof by checking features, cert authority, and GPO.

---

## Deliverable 6: Server Hardening

* Enable Windows Firewall for Domain, Public, and Private profiles.
* Allow only essential services through the firewall:

  * RDP (TCP 3389)
  * DNS (TCP & UDP 53)
  * DHCP Server (UDP 67)
  * HTTP (TCP 80) and HTTPS (TCP 443)

---

## Notes

* All passwords are preset to `Password1@` for demo purposes.
* Ensure all scripts are run in PowerShell with administrative privileges.
* Testing and validation commands are included in each `Proof` option.

---

## Authors

* Scripts developed and maintained by Prince
* For lab use only.

---
