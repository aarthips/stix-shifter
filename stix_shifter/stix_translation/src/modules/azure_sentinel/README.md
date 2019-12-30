# Azure Sentinel - ISC UDS Connector

### Data Source 
Microsoft Azure Sentinel is a scalable, cloud-native, security information event management (SIEM) and security orchestration automated response (SOAR) solution. Azure Sentinel delivers intelligent security analytics and threat intelligence across the enterprise, providing a single solution for alert detection, threat visibility, proactive hunting, and threat response.

##### Microsoft Graph API (v1.0)
List security alerts (GET call) https://graph.microsoft.com/v1.0/security/ <br/>
`Ref: https://docs.microsoft.com/en-us/graph/api/resources/alert?view=graph-rest-beta`

Query Parameter: 
$filter (OData V4.0 support) <br/>
`E.g. . GET /security/alerts?$filter={property} eq '{property-value}’` <br/>
`Ref: https://docs.microsoft.com/en-us/graph/query-parameters#filter-parameter`

Note: The Microsoft Graph Security API provides a unified interface and schema to integrate with security solutions from Microsoft and ecosystem partners. The security alerts from various partners are available and the schema comprises information about the fileStates, processes, networkConnections and userStates. <br/>
`Schema Ref: https://docs.microsoft.com/en-us/graph/api/alert-get?view=graph-rest-beta&tabs=http#example`

### Format for calling stix-shifter from the command line

python main.py `<translator_module>` `<query or result>` `<STIX identity object>` `<data>`

## Example I - Converting from STIX patterns to OData V4 queries (STIX attributes)
STIX to sentinel field mapping is defined in `from_stix_map.json` <br/>

This example input pattern:

`translate azure_sentinel query ‘{}’ "[process:name = 'svchost.exe'] START t'2019-01-01T08:43:10Z' STOP t'2019-12-31T08:43:10Z'"`

Returns the following Odata(native) query:

`{'queries': ["((processes/any(a1:a1/name eq 'svchost.exe') or fileStates/any(a1:a1/name eq 'svchost.exe'))) and (eventDateTime ge 2019-01-01T08:43:10Z and eventDateTime le 2019-12-31T08:43:10Z)"]}`

## Example I - Converting from Azure sentinel alerts to STIX (STIX attributes)

Sentinel data to STIX mapping is defined in `to_stix_map.json`

Sample data:

`translate azure_sentinel results "{\"type\":\"identity\",\"id\":\"identity--f431f809-377b-45e0-aa1c-6a4751cae5ff\",\"name\":\"azure_sentinel\",\"identity_class\":\"events\"}" "[{\"id\": \"2518268485253060642_52b1a353-2fd8-4c45-8f8a-94db98dca29d\", \"azureTenantId\": \"b73e5ba8-34d5-495a-9901-06bdb84cf13e\", \"azureSubscriptionId\": \"083de1fb-cd2d-4b7c-895a-2b5af1d091e8\", \"category\": \"SuspiciousSVCHOSTRareGroup\", \"createdDateTime\": \"2019-12-04T09:38:05.2024952Z\", \"description\": \"The system process SVCHOST was observed running a rare service group. Malware often use SVCHOST to masquerade its malicious activity.\", \"eventDateTime\": \"2019-12-04T09:37:54.6939357Z\", \"lastModifiedDateTime\": \"2019-12-04T09:38:06.7571701Z\", \"recommendedActions_0\": \"1. Run Process Explorer and try to identify unknown running processes (see https://technet.microsoft.com/en-us/sysinternals/bb896653.aspx)\", \"recommendedActions_1\": \"2. Make sure the machine is completely updated and has an updated anti-malware application installed\", \"recommendedActions_2\": \"3. Run a full anti-malware scan and verify that the threat was removed\", \"recommendedActions_3\": \"4. Install and run Microsoft’s Malicious Software Removal Tool (see https://www.microsoft.com/en-us/download/malicious-software-removal-tool-details.aspx)\", \"recommendedActions_4\": \"5. Run Microsoft’s Autoruns utility and try to identify unknown applications that are configured to run at login (see https://technet.microsoft.com/en-us/sysinternals/bb963902.aspx)\", \"severity\": \"informational\", \"status\": \"newAlert\", \"title\": \"Rare SVCHOST service group executed\", \"vendorInformation_provider\": \"ASC\", \"vendorInformation_subProvider\": \"Detection\", \"vendorInformation_vendor\": \"Microsoft\", \"fileStates_0_name\": \"services.exe\", \"fileStates_0_path\": \"c:\\windows\\system32\\services.exe\", \"fileStates_1_name\": \"svchost.exe\", \"fileStates_1_path\": \"c:\\windows\\system32\\svchost.exe\", \"hostStates_0_netBiosName\": \"TEST-WINDOW\", \"hostStates_0_os\": \"Windows\", \"processes_0_commandLine\": \"\", \"processes_0_name\": \"services.exe\", \"processes_0_path\": \"c:\\windows\\system32\\services.exe\", \"processes_1_accountName\": \"test-window$\", \"processes_1_commandLine\": \"c:\\windows\\system32\\svchost.exe -k clipboardsvcgroup -p -s cbdhsvc\", \"processes_1_createdDateTime\": \"2019-12-04T09:37:54.6939357Z\", \"processes_1_name\": \"svchost.exe\", \"processes_1_parentProcessName\": \"services.exe\", \"processes_1_path\": \"c:\\windows\\system32\\svchost.exe\", \"userStates_0_accountName\": \"test-window$\", \"userStates_0_domainName\": \"WORKGROUP\", \"userStates_0_emailRole\": \"unknown\", \"userStates_0_logonId\": \"0x3e7\", \"userStates_0_onPremisesSecurityIdentifier\": \"S-1-5-18\", \"userStates_0_userPrincipalName\": \"test-window$@TEST-WINDOW\", \"event_count\": \"1\"}, {\"id\": \"2518268485253060642_52b1a353-2fd8-4c45-8f8a-94db98dca29d\", \"azureTenantId\": \"b73e5ba8-34d5-495a-9901-06bdb84cf13e\", \"azureSubscriptionId\": \"083de1fb-cd2d-4b7c-895a-2b5af1d091e8\", \"category\": \"SuspiciousSVCHOSTRareGroup\", \"createdDateTime\": \"2019-12-04T09:38:05.2024952Z\", \"description\": \"The system process SVCHOST was observed running a rare service group. Malware often use SVCHOST to masquerade its malicious activity.\", \"eventDateTime\": \"2019-12-04T09:37:54.6939357Z\", \"lastModifiedDateTime\": \"2019-12-04T09:38:06.7571701Z\", \"recommendedActions_0\": \"1. Run Process Explorer and try to identify unknown running processes (see https://technet.microsoft.com/en-us/sysinternals/bb896653.aspx)\", \"recommendedActions_1\": \"2. Make sure the machine is completely updated and has an updated anti-malware application installed\", \"recommendedActions_2\": \"3. Run a full anti-malware scan and verify that the threat was removed\", \"recommendedActions_3\": \"4. Install and run Microsoft’s Malicious Software Removal Tool (see https://www.microsoft.com/en-us/download/malicious-software-removal-tool-details.aspx)\", \"recommendedActions_4\": \"5. Run Microsoft’s Autoruns utility and try to identify unknown applications that are configured to run at login (see https://technet.microsoft.com/en-us/sysinternals/bb963902.aspx)\", \"severity\": \"informational\", \"status\": \"newAlert\", \"title\": \"Rare SVCHOST service group executed\", \"vendorInformation_provider\": \"ASC\", \"vendorInformation_subProvider\": \"Detection\", \"vendorInformation_vendor\": \"Microsoft\", \"fileStates_0_name\": \"services.exe\", \"fileStates_0_path\": \"c:\\windows\\system32\\services.exe\", \"fileStates_1_name\": \"svchost.exe\", \"fileStates_1_path\": \"c:\\windows\\system32\\svchost.exe\", \"hostStates_0_netBiosName\": \"TEST-WINDOW\", \"hostStates_0_os\": \"Windows\", \"processes_0_commandLine\": \"\", \"processes_0_name\": \"services.exe\", \"processes_0_path\": \"c:\\windows\\system32\\services.exe\", \"processes_1_accountName\": \"test-window$\", \"processes_1_commandLine\": \"c:\\windows\\system32\\svchost.exe -k clipboardsvcgroup -p -s cbdhsvc\", \"processes_1_createdDateTime\": \"2019-12-04T09:37:54.6939357Z\", \"processes_1_name\": \"svchost.exe\", \"processes_1_parentProcessName\": \"services.exe\", \"processes_1_path\": \"c:\\windows\\system32\\svchost.exe\", \"userStates_0_accountName\": \"test-window$\", \"userStates_0_domainName\": \"WORKGROUP\", \"userStates_0_emailRole\": \"unknown\", \"userStates_0_logonId\": \"0x3e7\", \"userStates_0_onPremisesSecurityIdentifier\": \"S-1-5-18\", \"userStates_0_userPrincipalName\": \"test-window$@TEST-WINDOW\", \"event_count\": \"1\"}]" `

Will return the following STIX observable:

```json
{
    "type": "bundle",
    "id": "bundle--3d154ab5-1c20-4516-8c27-f050460e8d8d",
    "objects": [
        {
            "type": "identity",
            "id": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
            "name": "azure_sentinel",
            "identity_class": "events"
        },
        {
            "id": "observed-data--b4b392a5-d25c-453d-b34d-23029c5c167c",
            "type": "observed-data",
            "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
            "created": "2019-12-12T11:11:24.575Z",
            "modified": "2019-12-12T11:11:24.575Z",
            "objects": {
                "0": {
                    "type": "file",
                    "name": "services.exe",
                    "parent_directory_ref": "1"
                },
                "1": {
                    "type": "directory",
                    "path": "c:\\windows\\system32"
                },
                "2": {
                    "type": "file",
                    "name": "svchost.exe",
                    "parent_directory_ref": "3"
                },
                "3": {
                    "type": "directory",
                    "path": "c:\\windows\\system32"
                },
                "4": {
                    "type": "process",
                    "name": "services.exe",
                    "binary_ref": "0"
                },
                "5": {
                    "type": "process",
                    "name": "svchost.exe",
                    "parent_ref": "6",
                    "binary_ref": "2"
                },
                "6": {
                    "type": "process",
                    "name": "services.exe"
                },
                "7": {
                    "type": "user-account",
                    "user_id": "test-window$"
                }
            },
            "x_com_msazure_sentinel_alert": {
                "Sentinel_AlertId": "2518268485253060642_52b1a353-2fd8-4c45-8f8a-94db98dca29d",
                "Azure_TenantId": "b73e5ba8-34d5-495a-9901-06bdb84cf13e",
                "Azure_SubscriptionId": "083de1fb-cd2d-4b7c-895a-2b5af1d091e8",
                "Category": "SuspiciousSVCHOSTRareGroup",
                "Severity": "informational",
                "Alert_Title": "Rare SVCHOST service group executed",
                "Provider": "ASC",
                "Vendor": "Microsoft",
                "netBiosName": "TEST-WINDOW"
            },
            "first_observed": "2019-12-04T09:37:54.6939357Z",
            "last_observed": "2019-12-04T09:37:54.6939357Z",
            "number_observed": 1
        },
        {
            "id": "observed-data--68fe35df-31b3-4107-a33e-14f431666a37",
            "type": "observed-data",
            "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
            "created": "2019-12-12T11:11:24.575Z",
            "modified": "2019-12-12T11:11:24.575Z",
            "objects": {
                "0": {
                    "type": "file",
                    "name": "services.exe",
                    "parent_directory_ref": "1"
                },
                "1": {
                    "type": "directory",
                    "path": "c:\\windows\\system32"
                },
                "2": {
                    "type": "file",
                    "name": "svchost.exe",
                    "parent_directory_ref": "3"
                },
                "3": {
                    "type": "directory",
                    "path": "c:\\windows\\system32"
                },
                "4": {
                    "type": "process",
                    "name": "services.exe",
                    "binary_ref": "0"
                },
                "5": {
                    "type": "process",
                    "name": "svchost.exe",
                    "parent_ref": "6",
                    "binary_ref": "2"
                },
                "6": {
                    "type": "process",
                    "name": "services.exe"
                },
                "7": {
                    "type": "user-account",
                    "user_id": "test-window$"
                }
            },
            "x_com_msazure_sentinel_alert": {
                "Sentinel_AlertId": "2518268485253060642_52b1a353-2fd8-4c45-8f8a-94db98dca29d",
                "Azure_TenantId": "b73e5ba8-34d5-495a-9901-06bdb84cf13e",
                "Azure_SubscriptionId": "083de1fb-cd2d-4b7c-895a-2b5af1d091e8",
                "Category": "SuspiciousSVCHOSTRareGroup",
                "Severity": "informational",
                "Alert_Title": "Rare SVCHOST service group executed",
                "Provider": "ASC",
                "Vendor": "Microsoft",
                "netBiosName": "TEST-WINDOW"
            },
            "first_observed": "2019-12-04T09:37:54.6939357Z",
            "last_observed": "2019-12-04T09:37:54.6939357Z",
            "number_observed": 1
        }
    ]
} 
```


## Example II - Converting from STIX patterns to OData V4 queries (Custom attributes)
STIX to sentinel field mapping is defined in `from_stix_map.json` <br/>

This example input pattern:

`translate azure_sentinel query ‘{}’ "[x_com_msazure_sentinel_alert:category LIKE 'malware'] START t'2019-09-10T08:43:10.003Z' STOP t'2019-12-31T10:43:10.003Z’”`

Returns the following Odata(native) query:

`{'queries': ["(contains(category, 'malware')) and (eventDateTime ge 2019-09-10T08:43:10.003Z and eventDateTime le 2019-12-31T10:43:10.003Z)"]}`

## Example II - Converting from Azure sentinel alerts to STIX (Custom attributes)

Sentinel data to STIX mapping is defined in `to_stix_map.json`

Sample data:

`translate azure_sentinel results "{\"type\":\"identity\",\"id\":\"identity--f431f809-377b-45e0-aa1c-6a4751cae5ff\",\"name\":\"azure_sentinel\",\"identity_class\":\"events\"}" "[{\"id\": \"2518272831219999999_dc4a1ee7-a6dd-452f-56e5-17084a686d8c\", \"azureTenantId\": \"b73e5ba8-34d5-495a-9901-06bdb84cf13e\", \"azureSubscriptionId\": \"083de1fb-cd2d-4b7c-895a-2b5af1d091e8\", \"category\": \"AntimalwareActionTaken\", \"createdDateTime\": \"2019-11-29T09:08:55.359Z\", \"description\": \"Symantec Endpoint Protection has taken an action to protect this machine from malware or other potentially unwanted software.\", \"eventDateTime\": \"2019-11-29T08:54:38Z\", \"lastModifiedDateTime\": \"2019-11-29T09:08:56.4125734Z\", \"recommendedActions_0\": \"Contact your Symantec security administrator.\", \"severity\": \"low\", \"status\": \"newAlert\", \"title\": \"Antimalware Action Taken\", \"vendorInformation_provider\": \"ASC\", \"vendorInformation_subProvider\": \"Symantec\", \"vendorInformation_vendor\": \"Microsoft\", \"fileStates_0_name\": \"rs4_winatp-intro-invoice.docm\", \"fileStates_0_path\": \"c:\\users\\devadmin.test\\downloads\\rs4_winatp-intro-invoice.docm\", \"hostStates_0_fqdn\": \"lp-5cd80202zn.test.org.in\", \"hostStates_0_netBiosName\": \"lp-5cd80202zn\", \"malwareStates_0_name\": \"Trojan.Mdropper\", \"event_count\": \"1\"}]"`

Will return the following STIX observable:

```json
{
    "type": "bundle",
    "id": "bundle--7051f1ef-e6ad-459b-87ac-975c2ebdd52a",
    "objects": [
        {
            "type": "identity",
            "id": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
            "name": "azure_sentinel",
            "identity_class": "events"
        },
        {
            "id": "observed-data--3ef05b36-2faf-47ea-b056-68d415b50529",
            "type": "observed-data",
            "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
            "created": "2019-12-10T10:59:12.214Z",
            "modified": "2019-12-10T10:59:12.214Z",
            "objects": {
                "0": {
                    "type": "file",
                    "name": "rs4_winatp-intro-invoice.docm",
                    "parent_directory_ref": "1"
                },
                "1": {
                    "type": "directory",
                    "path": "c:\\users\\devadmin.test\\downloads"
                }
            },
            "x_com_msazure_sentinel_alert": {
                "Sentinel_AlertId": "2518272831219999999_dc4a1ee7-a6dd-452f-56e5-17084a686d8c",
                "Azure_TenantId": "b73e5ba8-34d5-495a-9901-06bdb84cf13e",
                "Azure_SubscriptionId": "083de1fb-cd2d-4b7c-895a-2b5af1d091e8",
                "Category": "AntimalwareActionTaken",
                "Severity": "low",
                "Alert_Title": "Antimalware Action Taken",
                "Provider": "ASC",
                "Vendor": "Microsoft",
                "netBiosName": "lp-5cd80202zn",
                "malwareName": "Trojan.Mdropper"
            },
            "first_observed": "2019-11-29T08:54:38Z",
            "last_observed": "2019-11-29T08:54:38Z",
            "number_observed": 1
        }
    ]
} 
```

Translated STIX attributes are inserted into the OData query in the order they are defined in the mapping file. <br/>

### Operator Support (Data Source)
| STIX Operator | Sample STIX expr | Sentinel Operator | Sample Native Expr |
| :---: | :---: | :---: | :---: |
| AND | [process:name = 'services.exe’] AND [network-traffic:dst_ref.value = '52.94.233.129']  | and | Both the observation expressions are handled as a single query joined with and operator. |
| OR | [process:name = 'services.exe’] OR [network-traffic:dst_ref.value = '52.94.233.129']  | or | Both the observation expressions are handled as a single query joined with or operator. |
| = | [network-traffic:dst_port=22]  | eq | networkConnections/any(q1:q1/destinationPort eq ‘22')  |
| != | [network-traffic:dst_port!=22]  | ne | networkConnections/any(q1:q1/destinationPort ne ‘22')  |
| '<' | [network-traffic:dst_port<22]  | lt | networkConnections/any(q1:q1/destinationPort lt ‘22')  |
| '>' | [network-traffic:dst_port>22]  | gt | networkConnections/any(q1:q1/destinationPort gt ‘22')  |
| '<=' | [network-traffic:dst_port<=22]  | le | networkConnections/any(q1:q1/destinationPort le ‘22') |
| '>=' | [network-traffic:dst_port>=22]  | ge | networkConnections/any(q1:q1/destinationPort ge ‘22') |
| IN | [network-traffic:dst_port IN (22, 3389)]  | eq(equals) with multiple (or) operator | networkConnections/any(a1:a1/destinationPort eq '22') or networkConnections/any(a1:a1/destinationPort eq '3389') |
| NOT IN | [network-traffic:dst_port NOT IN (22, 3389)]  | ne(not equals) with multiple (and) operator | networkConnections/any(a1:a1/destinationPort ne '22’) and networkConnections/any(a1:a1/destinationPort ne '3389' |
| LIKE, _: any one character, % - zero or more characters | process:name LIKE ‘%exe' | contains | processes/any(n:contains(n/name, 'exe')) |
| Matches | File:name MATCHES ‘.exe’ | contains | processes/any(n:contains(n/name, 'exe')) |
| NOT | network-traffic:dst_port NOT > 22 | Reversal of trailing operator behavior. | networkConnections/any(a1:a1/destinationPort le ‘22')  |
| ISSUBSET, ISSUPERSET | - | Not Supported | - |


### Odata query construction: IN clause

STIX attributes that map to multiple sentinel fields will have those fields joined by ORs in the returned query with comparator operator as 'equals' (custom logic) . <br/>

### Odata query construction: NOT IN clause

STIX attributes that map to multiple sentinel fields will have those fields joined by ANDs in the returned query with comparator operator as 'not equals' (custom logic). <br/>

### Odata query construction: NOT (negation) operator

STIX attributes that map to multiple sentinel fields will have those fields with comparator operator reversed. This reversal is effected for all the combinations (custom logic) <br/>

