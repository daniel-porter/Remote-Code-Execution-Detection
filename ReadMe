Project: Remote Code Execution Detection and Response

This project demonstrates how to detect and respond to potential Remote Code Execution (RCE) events using Microsoft Defender for Endpoint (MDE). The goal is to detect malicious PowerShell commands automating the download and execution of files, trigger alerts, and apply automated response actions like device isolation.
Steps:

    Setup a Windows Virtual Machine:
        Disable the Windows Firewall (wf.msc) to expose the VM for easier discovery.
        Onboard the VM to Microsoft Defender for Endpoint (MDE) for monitoring and response.
        Confirm the VM is successfully onboarded via the MDE Portal.

    Simulate RCE Activity:
        Run the following PowerShell command to simulate downloading and installing an application:

    cmd.exe /c powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Invoke-WebRequest -Uri 'https://sacyberrange00.blob.core.windows.net/vm-applications/7z2408-x64.exe' -OutFile C:\ProgramData\7z2408-x64.exe; Start-Process 'C:\programdata\7z2408-x64.exe' -ArgumentList '/S' -Wait"

Write a Detection Query: Use KQL to monitor for specific PowerShell commands on your VM:

    let VMName = "cyberlab";
    DeviceProcessEvents
    | where DeviceName == VMName
    | where InitiatingProcessCommandLine contains "Invoke-WebRequest" and InitiatingProcessCommandLine contains "Start-Process"

    Create a Detection Rule:
        Configure the detection rule to:
            Isolate the Device
            Collect an Investigation Package
        Ensure the rule applies only to your VM (e.g., cyberlab).

    Trigger the Detection Rule:
        Execute the PowerShell command from Step 2 to trigger the alert.
        Verify that the alert appears in the MDE portal under "Alerts."
        Check that the device is automatically isolated and an investigation package is created.

    Investigate and Resolve the Alert:
        Navigate to the VM in the MDE Portal.
        Review the Action Center and the Investigation Package.
        Assign the alert to your user account and mark it as resolved.

    Cleanup:
        Delete the custom detection rule.
        Release the VM from isolation.

Artifacts:

    Detection Query: KQL query
    Action Center Logs: Automated responses (e.g., device isolation).
    Investigation Package: Comprehensive forensic data for analysis.

## Remote Code Execution Detection Screenshots

### 1. PowerShell Command Execution
![PowerShell Command Execution](https://github.com/daniel-porter/Remote-Code-Execution-Detection/blob/main/Remote%20Code%20Execution%20Detection%20Screenshots/1.png?raw=true "PowerShell Execution Screenshot")

### 2. Detection Rule in Microsoft Defender
![Detection Rule](https://github.com/daniel-porter/Remote-Code-Execution-Detection/blob/main/Remote%20Code%20Execution%20Detection%20Screenshots/2.png?raw=true "Detection Rule Screenshot")

### 3. Investigation Package in Action Center
![Investigation Package](https://github.com/daniel-porter/Remote-Code-Execution-Detection/blob/main/Remote%20Code%20Execution%20Detection%20Screenshots/3.png?raw=true "Investigation Package Screenshot")

  

Screenshots are attached in this repository for reference.

This project demonstrates the effectiveness of custom detection rules in Microsoft Defender for Endpoint and showcases the end-to-end process of detecting, responding to, and analyzing potential RCE events.
