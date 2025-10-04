using namespace System.Net

#Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

$UserPrincipalName = $Request.Body.UserPrincipalName
$DeviceName = $Request.Body.DeviceName
if ($Request.Body.MicrosoftEntraIDAccessToken) {
    $Global:MicrosoftEntraIDAccessToken = $Request.Body.MicrosoftEntraIDAccessToken
}
else {
    try {
        $msiEndpoint = "http://169.254.169.254/metadata/identity/oauth2/token"
        $resource = "https://graph.microsoft.com/"
        $tokenUri = "$msiEndpoint?api-version=2018-02-01&resource=$([uri]::EscapeDataString($resource))"
        $tokenResponse = Invoke-RestMethod -Method GET -Uri $tokenUri -Headers @{ "Metadata" = "true" } -ErrorAction Stop

        if ($null -ne $tokenResponse.access_token) {
            $Global:MicrosoftEntraIDAccessToken = $tokenResponse.access_token
        }
        else {
            throw "Managed Identity did not return an access_token."
        }
    }
    catch {
        Write-Error "Failed to obtain Microsoft Graph token from Managed Identity: $($_.Exception.Message)"
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::Unauthorized
                Body       = @{ Message = "Failed to obtain token from Managed Identity" } | ConvertTo-Json
            })
        return
    }
}

if (-not $UserPrincipalName -and -not $DeviceName) {
    Write-Error "Both parameters UserPrincipalName and DeviceName are required."
    exit
}

#Get Intune Device By DeviceName
$IntuneDevice = Invoke-RestMethod -Method GET -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=startswith(deviceName,`'$DeviceName`')" -ContentType "Application/Json" -Headers @{Authorization = "Bearer $Global:MicrosoftEntraIDAccessToken" }

#Get Entra ID Device by AzureAdDeviceId from Intune Device
if ($IntuneDevice.value.Count -gt 0) {
    $IntuneDevice = $IntuneDevice.value[0]
    $EntraIDDevice = (Invoke-RestMethod -Method GET -Uri "https://graph.microsoft.com/v1.0/devices?`$filter=(deviceId eq '$($IntuneDevice.azureADDeviceId)')" -ContentType "Application/Json" -Headers @{Authorization = "Bearer $Global:MicrosoftEntraIDAccessToken" }).value
}
else {
    Write-Error "Zero or more than one device(s) found with name starting with '$DeviceName'"
    exit
}

#Naming Templates
$PolicyName = "Windows-COPE-LUSRMGR-$($IntuneDevice.serialNumber)"
$DeviceGroupName = "MEID-INT-Windows-LUSRMGR-$($IntuneDevice.serialNumber)"
$ExclusionGroupID = "d708d208-a415-4c08-9492-fa5b8b0629d5" # "MEID-INT-Windows-LUSRMGR-GlobalExclude"
$DefaultAdminGroupName = "MEID-INT-Windows-LUSRMGR-DefaultLocalAdmins"

#Global Control Functions
Function CheckGroupMember {
    Param($GroupIdentifier)
    
    # Check if the parameter is a GUID (Group ID) or a display name
    if ($GroupIdentifier -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
        # It's a GUID, use it directly as Group ID
        $GroupID = $GroupIdentifier
    }
    else {
        # It's a group name, look up the group by display name
        $GroupLookup = Invoke-RestMethod -Method GET -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$GroupIdentifier'" -ContentType "Application/Json" -Headers @{Authorization = "Bearer $Global:MicrosoftEntraIDAccessToken" }
        
        if ($GroupLookup.value.Count -eq 0) {
            Write-Warning "Group '$GroupIdentifier' not found"
            Return 0
        }
        $GroupID = $GroupLookup.value[0].id
    }
    
    # Then get the group members
    $Group = Invoke-RestMethod -Method GET -Uri "https://graph.microsoft.com/v1.0/groups/$GroupID/members" -ContentType "Application/Json" -Headers @{Authorization = "Bearer $Global:MicrosoftEntraIDAccessToken" }
    $Members = $Group.value
    while ($Group.'@odata.nextLink') {
        $Group = Invoke-RestMethod -Uri $Group.'@odata.nextLink' -Headers @{Authorization = "Bearer $Global:MicrosoftEntraIDAccessToken" }
        $Members += $Group.value
    }
    if ($Members.deviceId -contains $IntuneDevice.azureADDeviceId) {
        Return 1
    }
    else {
        Return 0
    }
}

Function CheckEntraIDGroup {
    Param($DeviceGroupName)
    $Group = Invoke-RestMethod -Method GET -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=startswith(displayName,`'$DeviceGroupName')" -ContentType "Application/Json" -Headers @{Authorization = "Bearer $Global:MicrosoftEntraIDAccessToken" }
    if ($Group.value.displayName -eq $DeviceGroupName) {
        Return 1
    }
    else {
        Return 0
    }
}

Function CheckAccountProtectionPolicy {
    Param($PolicyName)
    $Results = Invoke-RestMethod -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies" -ContentType "Application/Json" -Headers @{Authorization = "Bearer $Global:MicrosoftEntraIDAccessToken" }
    $ResultsValue = $results.value
    if ($results."@odata.nextLink" -ne $null) {
        $NextPageUri = $results."@odata.nextLink"
        ##While there is a next page, query it and loop, append results
        While ($NextPageUri -ne $null) {
            $NextPageRequest = (Invoke-RestMethod -Headers @{Authorization = "Bearer $Global:MicrosoftEntraIDAccessToken" } -Uri $NextPageURI -Method Get)
            $NxtPageData = $NextPageRequest.Value
            $NextPageUri = $NextPageRequest."@odata.nextLink"
            $ResultsValue = $ResultsValue + $NxtPageData
        }
    }
    $Policies = $ResultsValue

    if ($Policies.name -match $PolicyName) {
        Return 1
    }
    else {
        Return 0
    }
}

Function GetSIDByGroupName {
    Param($GroupName)
    $Group = Invoke-RestMethod -Method GET -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=startswith(displayName,`'$GroupName`')" -ContentType "Application/Json" -Headers @{Authorization = "Bearer $Global:MicrosoftEntraIDAccessToken" }
    return $Group.value.securityIdentifier
}

#Add Device to Exclusion Group
if (-not (CheckGroupMember $ExclusionGroupID)) {
    $ExclusionInformation = @"
    {
        "@odata.id":"https://graph.microsoft.com/v1.0/directoryObjects/$($EntraIDDevice.id)"
    }
"@
    $ResponseExclusionGroup = Invoke-RestMethod -Method Post -Uri "https://graph.microsoft.com/v1.0/groups/$($ExclusionGroupId)/members/`$ref" -ContentType "Application/Json" -Body $ExclusionInformation -Headers @{Authorization = "Bearer $Global:MicrosoftEntraIDAccessToken" }
}

#Create Group for Device
if (-not (CheckEntraIDGroup $DeviceGroupName)) {
    $Params = @{
        DisplayName = $DeviceGroupName
        Description = "Entra ID Group for LocalAdmin User Rights for Client $($IntuneDevice.value.serialNumber)"
    }
    
    $GroupInformation = @"
{
    "displayName": "$($params.DisplayName)",
    "description": "$($params.Description)",
    "mailEnabled": false,
    "mailNickname": "LocalUserRights",
    "securityEnabled": true,
    "members@odata.bind": [
        "https://graph.microsoft.com/v1.0/devices/$($EntraIDDevice.id)"
    ]
}
"@
    $ResponseGroup = Invoke-RestMethod -Method Post -Uri 'https://graph.microsoft.com/v1.0/groups' -ContentType "Application/Json" -Body $GroupInformation -Headers @{Authorization = "Bearer $Global:MicrosoftEntraIDAccessToken" }
}

#Add Device to Device Group
if (-not (CheckGroupMember $DeviceGroupName)) {
    $GroupInformation = @"
{
    "@odata.id":"https://graph.microsoft.com/v1.0/directoryObjects/$($EntraIDDevice.id)"
}
"@
    $ResponseGroup = Invoke-RestMethod -Method Post -Uri "https://graph.microsoft.com/v1.0/groups/$($ResponseGroup.id)/members/`$ref" -ContentType "Application/Json" -Body $GroupInformation -Headers @{Authorization = "Bearer $Global:MicrosoftEntraIDAccessToken" }
}

#Create Account Protection Policy
if (-not (CheckAccountProtectionPolicy $PolicyName)) {
    $PolicyInformation = @"
{
    "name": "$PolicyName",
    "description": "",
    "platforms": "windows10",
    "technologies": "mdm",
    "roleScopeTags":["0"],
    "settings": [
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_localusersandgroups_configure",
                "groupSettingCollectionValue": [
                    {
                        "children": [
                            {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance",
                                "settingDefinitionId": "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup",
                                "groupSettingCollectionValue": [
                                    {
                                        "children": [
                                            {
                                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                                                "settingDefinitionId": "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_userselectiontype",
                                                "choiceSettingValue": {
                                                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                                    "value": "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_userselectiontype_users",
                                                    "children": [
                                                        {
                                                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance",
                                                            "settingDefinitionId": "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_users",
                                                            "simpleSettingCollectionValue": [
                                                                {
                                                                    "value": "$(GetSIDByGroupName($DefaultAdminGroupName))",
                                                                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                                                                },
                                                                {
                                                                    "value": "AzureAD\\$UserPrincipalName",
                                                                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                                                                }
                                                            ]
                                                        }
                                                    ]
                                                }
                                            },
                                            {
                                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                                                "settingDefinitionId": "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_action",
                                                "choiceSettingValue": {
                                                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                                    "value": "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_action_add_update",
                                                    "children": []
                                                }
                                            },
                                            {
                                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingCollectionInstance",
                                                "settingDefinitionId": "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_desc",
                                                "choiceSettingCollectionValue": [
                                                    {
                                                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                                        "value": "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_desc_administrators",
                                                        "children": []
                                                    }
                                                ]
                                            }
                                        ]
                                    }
                                ],
                                "settingInstanceTemplateReference": {
                                    "settingInstanceTemplateId": "76fa254e-cbdb-4718-8bdd-cd41e57caa02"
                                }
                            }
                        ]
                    },
                    {
                        "children": [
                            {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance",
                                "settingDefinitionId": "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup",
                                "groupSettingCollectionValue": [
                                    {
                                        "children": [
                                            {
                                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                                                "settingDefinitionId": "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_userselectiontype",
                                                "choiceSettingValue": {
                                                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                                    "value": "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_userselectiontype_manual",
                                                    "children": [
                                                        {
                                                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance",
                                                            "settingDefinitionId": "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_users",
                                                            "simpleSettingCollectionValue": [
                                                                {
                                                                    "value": "local_admin",
                                                                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                                                                }
                                                            ]
                                                        }
                                                    ],
                                                    "settingValueTemplateReference": {
                                                        "settingValueTemplateId": "02908882-5aee-491c-a356-5833fe55ab93"
                                                    }
                                                },
                                                "settingInstanceTemplateReference": {
                                                    "settingInstanceTemplateId": "6f8c9cb0-3085-4476-ba18-6be49c87a1e6"
                                                }
                                            },
                                            {
                                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                                                "settingDefinitionId": "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_action",
                                                "choiceSettingValue": {
                                                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                                    "value": "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_action_add_update",
                                                    "children": [],
                                                    "settingValueTemplateReference": {
                                                        "settingValueTemplateId": "85c598ae-56d1-4715-b0c0-85bdadaec38d"
                                                    }
                                                },
                                                "settingInstanceTemplateReference": {
                                                    "settingInstanceTemplateId": "6c55c2ff-5ff9-4b08-a9b9-3fd2e2ce8405"
                                                }
                                            },
                                            {
                                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingCollectionInstance",
                                                "settingDefinitionId": "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_desc",
                                                "choiceSettingCollectionValue": [
                                                    {
                                                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                                        "value": "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_desc_administrators",
                                                        "children": []
                                                    }
                                                ],
                                                "settingInstanceTemplateReference": {
                                                    "settingInstanceTemplateId": "6c7f2209-31aa-4853-a49f-985264ce91ef"
                                                }
                                            }
                                        ]
                                    }
                                ],
                                "settingInstanceTemplateReference": {
                                    "settingInstanceTemplateId": "76fa254e-cbdb-4718-8bdd-cd41e57caa02"
                                }
                            }
                        ]
                    },
                ],
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "de06bec1-4852-48a0-9799-cf7b85992d45"
                }
            }
        }
    ],
    "templateReference": {
        "templateId": "22968f54-45fa-486c-848e-f8224aa69772_1"
    }
}
"@

    $ResponsePolicy = Invoke-RestMethod -Method Post -Uri 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies' -ContentType "Application/Json" -Body $PolicyInformation -Headers @{Authorization = "Bearer $Global:MicrosoftEntraIDAccessToken" }

    #Assign Entra ID to Account Protection Policy
    $AssignmentInformation = @"
{
    "assignments": [
        {
            "target": {
                "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                "groupId": "$($ResponseGroup.id)"
            }
        }
        ]
}
"@
    $ResponseConfigAssignment = Invoke-RestMethod -Method Post -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$($ResponsePolicy.id)')/assign" -ContentType "Application/Json" -Body $AssignmentInformation -Headers @{Authorization = "Bearer $Global:MicrosoftEntraIDAccessToken" }
}
else {
    #Get Current Element
    $Results = Invoke-RestMethod -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies" -ContentType "Application/Json" -Headers @{Authorization = "Bearer $Global:MicrosoftEntraIDAccessToken" }
    $ResultsValue = $results.value
    if ($results."@odata.nextLink" -ne $null) {
        $NextPageUri = $results."@odata.nextLink"
        ##While there is a next page, query it and loop, append results
        While ($NextPageUri -ne $null) {
            $NextPageRequest = (Invoke-RestMethod -Headers @{Authorization = "Bearer $Global:MicrosoftEntraIDAccessToken" } -Uri $NextPageUri -Method Get)
            $NxtPageData = $NextPageRequest.Value
            $NextPageUri = $NextPageRequest."@odata.nextLink"
            $ResultsValue = $ResultsValue + $NxtPageData
        }
    }
    $Policies = $ResultsValue
    Foreach ($policyobject in $Policies) {
        if ($policyobject.name -eq $PolicyName) {
            $Policy = $policyobject
        }
    }
    $PolicySettings = Invoke-RestMethod -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$($policy.id)')/settings" -ContentType "Application/Json" -Headers @{Authorization = "Bearer $Global:MicrosoftEntraIDAccessToken" }

    if (-not ($PolicySettings.value.settingInstance.groupSettingCollectionValue[0].children.groupSettingCollectionValue.children.choiceSettingValue.children.simpleSettingCollectionValue.value -contains "AzureAD\$UserPrincipalName")) {
        $newMember = new-object -TypeName PSObject
        $newMember | add-member -MemberType NoteProperty -Name "@odata.type" -value "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
        $newMember | add-member -MemberType NoteProperty -Name 'value' -value "AzureAD\$UserPrincipalName"
        $PolicySettings.value.settingInstance.groupSettingCollectionValue[0].children.groupSettingCollectionValue.children.choiceSettingValue.children.simpleSettingCollectionValue += $newMember
        $JsonPolicyUpdate = ConvertTo-Json $PolicySettings.value.settingInstance.groupSettingCollectionValue[0].children.groupSettingCollectionValue.children.choiceSettingValue.children.simpleSettingCollectionValue
        $PolicyUpdateInformation = @"
{
    "name": "$PolicyName",
    "description": "",
    "platforms": "windows10",
    "technologies": "mdm",
    "roleScopeTags":["0"],
    "settings": [
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_localusersandgroups_configure",
                "groupSettingCollectionValue": [
                    {
                        "children": [
                            {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance",
                                "settingDefinitionId": "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup",
                                "groupSettingCollectionValue": [
                                    {
                                        "children": [
                                            {
                                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                                                "settingDefinitionId": "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_userselectiontype",
                                                "choiceSettingValue": {
                                                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                                    "value": "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_userselectiontype_users",
                                                    "children": [
                                                        {
                                                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance",
                                                            "settingDefinitionId": "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_users",
                                                            "simpleSettingCollectionValue":
                                                                $JsonPolicyUpdate
                                                        }
                                                    ]
                                                }
                                            },
                                            {
                                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                                                "settingDefinitionId": "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_action",
                                                "choiceSettingValue": {
                                                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                                    "value": "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_action_add_update",
                                                    "children": []
                                                }
                                            },
                                            {
                                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingCollectionInstance",
                                                "settingDefinitionId": "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_desc",
                                                "choiceSettingCollectionValue": [
                                                    {
                                                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                                        "value": "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_desc_administrators",
                                                        "children": []
                                                    }
                                                ]
                                            }
                                        ]
                                    }
                                ],
                                "settingInstanceTemplateReference": {
                                    "settingInstanceTemplateId": "76fa254e-cbdb-4718-8bdd-cd41e57caa02"
                                }
                            }
                        ]
                    },
                    {
                        "children": [
                            {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance",
                                "settingDefinitionId": "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup",
                                "groupSettingCollectionValue": [
                                    {
                                        "children": [
                                            {
                                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                                                "settingDefinitionId": "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_userselectiontype",
                                                "choiceSettingValue": {
                                                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                                    "value": "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_userselectiontype_manual",
                                                    "children": [
                                                        {
                                                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance",
                                                            "settingDefinitionId": "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_users",
                                                            "simpleSettingCollectionValue": [
                                                                {
                                                                    "value": "local_admin",
                                                                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                                                                }
                                                            ]
                                                        }
                                                    ],
                                                    "settingValueTemplateReference": {
                                                        "settingValueTemplateId": "02908882-5aee-491c-a356-5833fe55ab93"
                                                    }
                                                },
                                                "settingInstanceTemplateReference": {
                                                    "settingInstanceTemplateId": "6f8c9cb0-3085-4476-ba18-6be49c87a1e6"
                                                }
                                            },
                                            {
                                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                                                "settingDefinitionId": "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_action",
                                                "choiceSettingValue": {
                                                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                                    "value": "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_action_add_update",
                                                    "children": [],
                                                    "settingValueTemplateReference": {
                                                        "settingValueTemplateId": "85c598ae-56d1-4715-b0c0-85bdadaec38d"
                                                    }
                                                },
                                                "settingInstanceTemplateReference": {
                                                    "settingInstanceTemplateId": "6c55c2ff-5ff9-4b08-a9b9-3fd2e2ce8405"
                                                }
                                            },
                                            {
                                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingCollectionInstance",
                                                "settingDefinitionId": "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_desc",
                                                "choiceSettingCollectionValue": [
                                                    {
                                                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                                        "value": "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_desc_administrators",
                                                        "children": []
                                                    }
                                                ],
                                                "settingInstanceTemplateReference": {
                                                    "settingInstanceTemplateId": "6c7f2209-31aa-4853-a49f-985264ce91ef"
                                                }
                                            }
                                        ]
                                    }
                                ],
                                "settingInstanceTemplateReference": {
                                    "settingInstanceTemplateId": "76fa254e-cbdb-4718-8bdd-cd41e57caa02"
                                }
                            }
                        ]
                    }
                ],
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "de06bec1-4852-48a0-9799-cf7b85992d45"
                }
            }
        }
    ],
    "templateReference": {
        "templateId": "22968f54-45fa-486c-848e-f8224aa69772_1"
    }
}
"@
        $PolicySettings = Invoke-RestMethod -Method PUT -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$($policy.id)')" -ContentType "Application/Json" -Body $PolicyUpdateInformation -Headers @{Authorization = "Bearer $Global:MicrosoftEntraIDAccessToken" }
    }
}

# Check if everything worked
if ((CheckEntraIDGroup $DeviceGroupName) -ne 1) {
    $outputtext = "FINAL CHECK: Error while creating Group"
}
elseif ((CheckAccountProtectionPolicy $PolicyName) -ne 1) {
    $outputtext = "FINAL CHECK: Error while creating Account Protection Policy"
}
elseif ((CheckGroupMember $DeviceGroupName) -ne 1) {
    $outputtext = "FINAL CHECK: Error while granting member to group"
}
elseif ((CheckGroupMember $ExclusionGroupID) -ne 1) {
    $outputtext = "FINAL CHECK: Error while adding member to exclusion group"
}
else {
    $outputtext = "FINAL CHECK: SUCCESS"
}

Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body       = $outputtext
    })