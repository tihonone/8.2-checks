# 8.2-checks


Name: 01_network_directory_traversal
Privileges: local admin
IoA: file_and_directory_discovery_via_powershell_amsi
Execution:
Note:
***

Name: 02_runkey_persistence 
Privileges: local admin
IoA: explorer_tools_persistence
Execution:
Note: before reverting changes go to: Computer -> System drive -> Properties -> Tools -> backup: notepad should be opened
***

Name:03_SILENT-outbound_from_unsigned_temporary_directory
Privileges: local user
IoA: powershell_with_network_activity AND powershell_cmdline_executionpolicy_bypass
Execution:
Note:   there won't be alert because this IoA has only telemetry markup, to find related event with silen IoA tag go to threat hunting an run follosing querry:

```
SELECT *
FROM `events`
WHERE has(IoAId, '0948CB7E-EA4C-A51B-C6AD-B55EA062A215') OR has(IoAId, '065EB351-1AEB-85DA-4280-67FE03A31B6C')
ORDER BY Timestamp DESC
LIMIT 250  
```

==event with "connection" type is actuall network connection, with "process" - script execution==
***

Name: 04_modify_registry_using_cli_registry_tool
Privileges: local admin
IoA: add_netsh_helper_dll
Execution: ./04_modify_registry_using_cli_registry_tool.ps1 -ConfirmLabVM
Note: execute script on test VM only, prepare VM snapshot BEFORE script execution, do not execute netsh before cleaning up and removing fake files.

Name: 06_registing_time_provider_DLL
Privileges: local admin
IoA: persistence_via_time_provider_registry_key
Execution: ./06_registing_time_provider_DLL.ps1
Note:
- The test does not load or run a DLL as an active provider. This is intentional: it avoids creating persistence or interfering with the Windows Time service.
- DllName points only to the standard W32Time.dll. No files are copied to %TEMP%, %SystemRoot%, or any other directory.
- Enabled is always set to 0. Do not change it to 1 for this safe test.
The test does not change any services, scheduled tasks, svchost.exe processes, network connections, or the system time.
***

Name: 07_unexpected_services.exe_parent
Privileges0: local user
IoA: suspicious_parent_processes, anomaly_in_the_windows_critical_process_tree, create_file_named_like_system_tool_in_wrong_place
Execution: ./07_unexpected_services.exe_parent.ps1
Note: three alerts will bi rised
***

Name: 09_SILENT_PowerShell_command_using_string_manipulation
Privileges: local user
IoA: encoded_powershell_code_execution_amsi
Execution: ./09_SILENT_PowerShell_command_using_string_manipulation.ps1
Note: there won't be alert because this IoA has only telemetry markup, to find related event with silen IoA tag go to threat hunting an run follosing querry:

```
SELECT *
FROM `events`
WHERE has(IoAId, '06A97C7B-A172-49C5-B925-F80F28CC8FE7')
ORDER BY Timestamp DESC
LIMIT 250  
```
***

Name: 10_unexpected_runtimebroker.exe_parent
Privileges: local user
IoA: suspicious_parent_processes
Execution: ./10_unexpected_runtimebroker.exe_parent.ps1
Note: 
Stop runtimebroker.exe after execution, then you'll have an alert in solution console
Unexpected runtimebroker.exe Parent — safe reversible lab EDR test
Copies the Microsoft-signed RuntimeBroker.exe to a dedicated temporary directory.
Launches the copy through cmd.exe without arguments to simulate an unexpected parent process.
Does not interact with Windows Runtime, UWP/AppX, services, registry, network, or system processes.
The copied process may exit quickly and return a non-zero exit code.
***

Name: 12_registering_boot_execute
Privileges: local admin
IoA: bootexecute_registry_keys_set
Execution: ./12_registering_boot_execute.ps1
Note: each step in script requires explicit confirmation by inreactive input - YES. The script reverts all changes back to defaults but it must be executed on VM with default snapshot created before script execution.

***

Name: 13_write_executable_to_recycle_bin_directory
Privileges: local user
IoA: possible_renamed_interpreter, not_standard_directory_archive(log entry only), archiving_files_in_recycle_via_archive, powershell_cmdline_executionpolicy_bypass(log entry only)
Execution: ./13_write_executable_to_recycle_bin_directory.ps1
Note: two alerts will be rised, additionally two log entries with mark up will be generated. If you need to regenerate alerts, reboot target host and execute the script once again.
***

Name: 14_lateral_movement_with_credentials_using_net_utility
Privileges: local user
IoA: network_share_discovery_via_standard_windows_utilities (log entry only)
Execution: ./14_lateral_movement_with_credentials_using_net_utility.ps1
Note:

Two hosts are required. Host1 - hosting windows share accessible from host2. Host 2 (target host) is used to execute testing script. host1 ip address, share name, credentials will be requested interactively during script execution.

After script execution execute following threat hunting querry to locate relevant event and display all connected events on the process tree:

```
SELECT *
FROM `events`
WHERE has(IoAId, 'EAF1B598-81BC-4DCD-9183-35B9444EF52B')
ORDER BY Timestamp DESC
LIMIT 250
```

custom correlation rule can be used to rise alerts based on such events.
***

Name: 16_unexpected_smss.exe_parent
Privileges: local user 
IoA: windows_command_shell_usage(log entry only),anomaly_in_the_windows_critical_process_tree, suspicious_parent_processes, create_file_named_like_system_tool_in_wrong_place
Execution: ./16_unexpected_smss.exe_parent.ps1
Note: thre alerts will be rised, use any to reveal all conneted events on single process tree.
***

Name: 18_modify_winlogon_registry_settings 
Privileges: local admin
IoA: change_winlogon_helper_dll_via_registry, collecting_credentials_from_registry_via_reg, query_registry_for_stored_credentials_via_powershell
Execution: ./18_modify_winlogon_registry_settings.ps1
Note: execute this script only in testing VM with initial state snapshot available!
***

Name:
Privileges:
IoA:
Execution:
Note:
***