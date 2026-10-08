# 8.2-checks


Name: 01_network_directory_traversal<br />
Privileges: local admin<br />
IoA: file_and_directory_discovery_via_powershell_amsi<br />
Execution:./01_network_directory_traversal.ps1<br />
Note:<br />
***

Name: 03_runkey_persistence <br />
Privileges: local admin<br />
IoA: explorer_tools_persistence<br />
Execution:./03_runkey_persistence.ps1 <br />
Note: before reverting changes go to: Computer -> System drive -> Properties -> Tools -> backup: notepad should be opened<br />
***

Name:04_SILENT-outbound_from_unsigned_temporary_directory<br />
Privileges: local user<br />
IoA: powershell_with_network_activity AND powershell_cmdline_executionpolicy_bypass<br />
Execution:./04_SILENT-outbound_from_unsigned_temporary_directory.ps1<br />
Note:   there won't be alert because this IoA has only telemetry markup, to find related event with silen IoA tag go to threat hunting an run following querry:<br />

```
SELECT *
FROM `events`
WHERE has(IoAId, '0948CB7E-EA4C-A51B-C6AD-B55EA062A215') OR has(IoAId, '065EB351-1AEB-85DA-4280-67FE03A31B6C')
ORDER BY Timestamp DESC
LIMIT 250  
```

__event with "connection" type is actuall network connection, with "process" - script execution__<br />
***

Name: 05_modify_registry_using_cli_registry_tool <br />
Privileges: local admin <br />
IoA: add_netsh_helper_dll <br />
Execution: ./04_modify_registry_using_cli_registry_tool.ps1 -ConfirmLabVM <br />
Note: execute script on test VM only, prepare VM snapshot BEFORE script execution, do not execute netsh before cleaning up and removing fake files.  <br />
***

Name: 06_registing_time_provider_DLL<br />
Privileges: local admin <br />
IoA: persistence_via_time_provider_registry_key<br />
Execution: ./06_registing_time_provider_DLL.ps1<br />
Note:
- The test does not load or run a DLL as an active provider. This is intentional: it avoids creating persistence or interfering with the Windows Time service.
- DllName points only to the standard W32Time.dll. No files are copied to %TEMP%, %SystemRoot%, or any other directory.
- Enabled is always set to 0. Do not change it to 1 for this safe test.
The test does not change any services, scheduled tasks, svchost.exe processes, network connections, or the system time.
***

Name: 07_unexpected_services.exe_parent<br />
Privileges0: local user<br />
IoA: suspicious_parent_processes, anomaly_in_the_windows_critical_process_tree, create_file_named_like_system_tool_in_wrong_place<br />
Execution: ./07_unexpected_services.exe_parent.ps1<br />
Note: three alerts will bi rised<br />
***

Name: 09_SILENT_PowerShell_command_using_string_manipulation<br />
Privileges: local user<br />
IoA: encoded_powershell_code_execution_amsi<br />
Execution: ./09_SILENT_PowerShell_command_using_string_manipulation.ps1<br />
Note: there won't be alert because this IoA has only telemetry markup, to find related event with silen IoA tag go to threat hunting an run follosing querry:<br />

```
SELECT *
FROM `events`
WHERE has(IoAId, '06A97C7B-A172-49C5-B925-F80F28CC8FE7')
ORDER BY Timestamp DESC
LIMIT 250  
```
***

Name: 10_unexpected_runtimebroker.exe_parent<br />
Privileges: local user<br />
IoA: suspicious_parent_processes<br />
Execution: ./10_unexpected_runtimebroker.exe_parent.ps1<br />
Note: <br />
Stop runtimebroker.exe after execution, then you'll have an alert in solution console
Unexpected runtimebroker.exe Parent — safe reversible lab EDR test
Copies the Microsoft-signed RuntimeBroker.exe to a dedicated temporary directory.
Launches the copy through cmd.exe without arguments to simulate an unexpected parent process.
Does not interact with Windows Runtime, UWP/AppX, services, registry, network, or system processes.
The copied process may exit quickly and return a non-zero exit code.
***

Name: 12_registering_boot_execute<br />
Privileges: local admin<br />
IoA: bootexecute_registry_keys_set<br />
Execution: ./12_registering_boot_execute.ps1<br />
Note: each step in script requires explicit confirmation by inreactive input - YES. The script reverts all changes back to defaults but it must be executed on VM with default snapshot created before script execution.<br />

***

Name: 13_write_executable_to_recycle_bin_directory<br />
Privileges: local user<br />
IoA: possible_renamed_interpreter, not_standard_directory_archive(log entry only), archiving_files_in_recycle_via_archive, powershell_cmdline_executionpolicy_bypass(log entry only)<br />
Execution: ./13_write_executable_to_recycle_bin_directory.ps1<br />
Note: two alerts will be rised, additionally two log entries with mark up will be generated. If you need to regenerate alerts, reboot target host and execute the script once again.<br />
***

Name: 14_lateral_movement_with_credentials_using_net_utility<br />
Privileges: local user<br />
IoA: network_share_discovery_via_standard_windows_utilities (log entry only)<br />
Execution: ./14_lateral_movement_with_credentials_using_net_utility.ps1<br />
Note:<br />

Two hosts are required. Host1 - hosting windows share accessible from host2. Host 2 (target host) is used to execute testing script. host1 ip address, share name, credentials will be requested interactively during script execution.

After script execution execute following threat hunting querry to locate relevant event and display all connected events on the process tree:
<br />
```
SELECT *
FROM `events`
WHERE has(IoAId, 'EAF1B598-81BC-4DCD-9183-35B9444EF52B')
ORDER BY Timestamp DESC
LIMIT 250
```
<br />
custom correlation rule can be used to rise alerts based on such events.
***

Name: 16_unexpected_smss.exe_parent<br />
Privileges: local user <br />
IoA: windows_command_shell_usage(log entry only),anomaly_in_the_windows_critical_process_tree, suspicious_parent_processes, create_file_named_like_system_tool_in_wrong_place<br />
Execution: ./16_unexpected_smss.exe_parent.ps1<br />
Note: thre alerts will be rised, use any to reveal all conneted events on single process tree.<br />
*** <br />
Name: 17_autorun_unsigned_servicedll<br />
Priviliges: local admin <br />
IoA: change_service_binary_location_in_registry, 
Preparation: download from: , and put ps1 script and downloaded EDR_Unsigned_Module.dll and spoolsv.exe into same folder
Execution:<br />
```
& 'C:\<path>\<to>\<containing>\<folder>\EDRSafeUnsignedServiceDllTest.ps1' `
    -SourceDllPath 'C:\<path>\<to>\<containing>\<folder>\EDR_Unsigned_Module.dll' `
    -LoaderExePath 'C:\<path>\<to>\<containing>\<folder>\spoolsv.exe' `
    -HoldSeconds 60 `
    -KeepArtifacts 
```
Note1: Run this script in test VM with clean snapshot available!
Note2: Pay attention to paths added as script execution arguments, adjust them accordingly.
Note3: You may use -KeepArtifacts to keep all changes made by the script for later demonstration.
Note4: Clean the system, using script named: 17_1_artifacts_cleanup_autorun_unsigned_servicedll, before the next script execution.
***
<br />
Name: 18_modify_winlogon_registry_settings <br />
Privileges: local admin<br />
IoA: change_winlogon_helper_dll_via_registry, collecting_credentials_from_registry_via_reg, query_registry_for_stored_credentials_via_powershell<br />
Execution: ./18_modify_winlogon_registry_settings.ps1<br />
Note: __execute this script only in testing VM with initial state snapshot available!__<br />
***

Name:
Privileges:
IoA:
Execution:
Note:
***