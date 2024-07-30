
# Features

- Continuously monitors Active Directory to detect changes to domain controllers, organizational units (OUs), groups, and Group Policy Objects (GPOs).
- Records all monitoring and approval activities in detailed logs, including audit information for investigative purposes.
- Compares the current state of Active Directory to a predefined baseline and records any changes.

![Tela](https://github.com/user-attachments/assets/3bb13c71-bf24-47d3-aff6-35f63a038f9b)

![Tela2](https://github.com/user-attachments/assets/55d922e5-9ada-4f74-bd5b-77e8bb6ea49e)

# Prerequisites

- Windows PowerShell 5.1 or higher.
- Administrative access to Active Directory.

# Configuração

- Download the file to your local machine.
- Modify global settings: Open the ADMonitor.ps1 file and edit the following variables according to your environment:
- $global:logDirectory: Path to the directory where the logs will be stored.
- $global:authorizedApprovers: List of administrator accounts authorized to start monitoring and approve changes.
- $global:authorizedReverters: List of administrator accounts authorized to revert changes.

# Running

- Open PowerShell with administrative privileges.
- Run the main script: Type the following command and press Enter:
  
          .\ADMonitor.ps1

- The CLI interface will display a menu with several options, including start/stop monitoring, generate baseline, view logs, and approve changes.
- Note: Only authorized administrators can start monitoring and approve changes.

# Security Considerations

- The tool uses PowerShell's restricted execution feature to improve security.
- Administrator passwords are not stored anywhere in the code.
- Audit logs record all monitoring and approval activities for investigation purposes.
- Only authorized administrators can start monitoring and approve changes.

# Contributing

- We value your contribution, if you have suggestions for improvements or corrections, feel free to contribute or open an issue.
