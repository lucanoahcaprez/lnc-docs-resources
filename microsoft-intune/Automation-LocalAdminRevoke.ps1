using namespace System.Net

# Input bindings are passed in via param block.
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

#Get Entra ID Device by EntraIDDeviceId from Intune Device
if ($IntuneDevice.value.Count -gt 0) {
    $IntuneDevice = $IntuneDevice.value[0]
    $EntraIDDevice = (Invoke-RestMethod -Method GET -Uri "https://graph.microsoft.com/v1.0/devices?`$filter=(deviceId eq '$($IntuneDevice.AzureADDeviceId)')" -ContentType "Application/Json" -Headers @{Authorization = "Bearer $Global:MicrosoftEntraIDAccessToken" }).value
}
else {
    Write-Error "Zero or more than one device(s) found with name starting with '$DeviceName'"
    exit
}

# Naming Templates
$PolicyName = "Windows-COPE-LUSRMGR-$($IntuneDevice.serialNumber)"
$DeviceGroupName = "MEID-INT-Windows-LUSRMGR-$($IntuneDevice.serialNumber)"
$ExclusionGroupID = "d708d208-a415-4c08-9492-fa5b8b0629d5" # "MEID-INT-Windows-LUSRMGR-GlobalExclude"

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
    Param($GroupName)
    $Group = Invoke-RestMethod -Method GET -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=startswith(displayName,`'$GroupName')" -ContentType "Application/Json" -Headers @{Authorization = "Bearer $Global:MicrosoftEntraIDAccessToken" }
    if ($Group.value.displayName -eq $GroupName) {
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

Function CheckOnlyPolicyMember {
    Param($PolicyName)
    $Results = Invoke-RestMethod -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies" -ContentType "Application/Json" -Headers @{Authorization = "Bearer $Global:MicrosoftEntraIDAccessToken" }
    $ResultsValue = $results.value
    if ($results."@odata.nextLink" -ne $null) {
        $NextPageUri = $results."@odata.nextLink"
        ##While there is a next page, query it and loop, append results
        While ($NextPageUri -ne $null) {
            $NextPageRequest = (Invoke-RestMethod -Headers @{Authorization = "Bearer $($Global:MicrosoftEntraIDAccessToken)" } -Uri $NextPageURI -Method Get)
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
    $PolicySettings = Invoke-RestMethod -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$($Policy.id)')/settings" -ContentType "Application/Json" -Headers @{Authorization = "Bearer $Global:MicrosoftEntraIDAccessToken" }
    # Get admin members from all groupSettingCollectionValue elements
    $AllAdminMembers = @()
    foreach ($groupSetting in $PolicySettings.value.settingInstance.groupSettingCollectionValue) {
        if ($groupSetting.children.groupSettingCollectionValue.children.choiceSettingValue.children.simpleSettingCollectionValue.value) {
            $AllAdminMembers += $groupSetting.children.groupSettingCollectionValue.children.choiceSettingValue.children.simpleSettingCollectionValue.value
        }
    }
    $MemberCount = [regex]::Matches($AllAdminMembers, "AzureAD" ).count
    if ($MemberCount -eq 1) {
        Return 1
    }
    else {
        Return 0
    }
}

# Check if Email is only Member
# Delete Policy, Group and remove Member of Exlcusion Group
if (CheckOnlyPolicyMember $PolicyName) {
    if (CheckEntraIDGroup $DeviceGroupName) {
        $Group = Invoke-RestMethod -Method GET -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=startswith(displayName,`'$DeviceGroupName`')" -ContentType "Application/Json" -Headers @{Authorization = "Bearer $Global:MicrosoftEntraIDAccessToken" }
        $ResponseGroup = Invoke-RestMethod -Method Delete -Uri "https://graph.microsoft.com/v1.0/groups/$($Group.value.id)" -ContentType "Application/Json" -Body $GroupInformation -Headers @{Authorization = "Bearer $Global:MicrosoftEntraIDAccessToken" }
    }
    #Remove Device from Exclusion Group
    $ResponseExclusionGroup = Invoke-RestMethod -Method Delete -Uri "https://graph.microsoft.com/v1.0/groups/$($ExclusionGroupID)/members/$($EntraIDDevice[0].id)/`$ref" -ContentType "Application/Json" -Headers @{Authorization = "Bearer $Global:MicrosoftEntraIDAccessToken" }

    #Delete Account Protection Policy
    $Results = Invoke-RestMethod -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies" -ContentType "Application/Json" -Headers @{Authorization = "Bearer $Global:MicrosoftEntraIDAccessToken" }
    $ResultsValue = $results.value
    if ($results."@odata.nextLink" -ne $null) {
        $NextPageUri = $results."@odata.nextLink"
        ##While there is a next page, query it and loop, append results
        While ($NextPageUri -ne $null) {
            $NextPageRequest = (Invoke-RestMethod -Headers @{Authorization = "Bearer $($Global:MicrosoftEntraIDAccessToken)" } -Uri $NextPageURI -Method Get)
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
    $PolicyDeletion = Invoke-RestMethod -Method DELETE -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$($Policy.id)')" -ContentType "Application/Json" -Headers @{Authorization = "Bearer $Global:MicrosoftEntraIDAccessToken" }
    
    if (CheckEntraIDGroup $DeviceGroupName) {
        $outputtext = "Case1Deletion: Error Entra ID Group for Device is not deleted correctly."
    }
    elseif (CheckAccountProtectionPolicy $PolicyName) {
        $outputtext = "Case1Deletion: Error Account Protection Policy is not deleted correctly."
    }
    elseif (CheckGroupMember $ExclusionGroupName) {
        $outputtext = "Case1Deletion: Error Entra ID Exclusion Group does still contain the Device."
    }
}
else {
    #Get Current Element
    $Results = Invoke-RestMethod -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies" -ContentType "Application/Json" -Headers @{Authorization = "Bearer $Global:MicrosoftEntraIDAccessToken" }
    $ResultsValue = $results.value
    if ($results."@odata.nextLink" -ne $null) {
        $NextPageUri = $results."@odata.nextLink"
        ##While there is a next page, query it and loop, append results
        While ($NextPageUri -ne $null) {
            $NextPageRequest = (Invoke-RestMethod -Headers @{Authorization = "Bearer $($Global:MicrosoftEntraIDAccessToken)" } -Uri $NextPageURI -Method Get)
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
    $PolicySettings = Invoke-RestMethod -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$($Policy.id)')/settings" -ContentType "Application/Json" -Headers @{Authorization = "Bearer $Global:MicrosoftEntraIDAccessToken" }

    if ($PolicySettings.value.settingInstance.groupSettingCollectionValue[0].children.groupSettingCollectionValue.children.choiceSettingValue.children.simpleSettingCollectionValue.value -contains "AzureAD\$UserPrincipalName") {
        # Get admin members from all groupSettingCollectionValue elements
        $AllAdminMembers = $PolicySettings.value.settingInstance.groupSettingCollectionValue[0].children.groupSettingCollectionValue.children.choiceSettingValue.children.simpleSettingCollectionValue

        $newMembers = @()
        Foreach ($Member in $AllAdminMembers) {
            $Member
            if ($Member.value -ne "AzureAD\$UserPrincipalName") {
                $newMember = New-Object psobject -Property @{
                    "@odata.type" = $Member."@odata.type"
                    "value"       = $Member.value
                }
                $newMembers += $newMember
            }
        }
        $PolicySettings.value.settingInstance.groupSettingCollectionValue[0].children.groupSettingCollectionValue.children.choiceSettingValue.children.simpleSettingCollectionValue = $newMembers
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
        $PolicySettings = Invoke-RestMethod -Method PUT -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$($Policy.id)')" -ContentType "Application/Json" -Body $PolicyUpdateInformation -Headers @{Authorization = "Bearer $Global:MicrosoftEntraIDAccessToken" }
        
        if (-not (CheckEntraIDGroup $DeviceGroupName)) {
            $outputtext = "Case2Deletion: Error Entra ID Group for Device is not present anymore."
        }
        elseif (-not (CheckAccountProtectionPolicy $PolicyName)) {
            $outputtext = "Case2Deletion: Error Account Protection Policy is not present anymore."
        }
        elseif ((CheckGroupMember $ExclusionGroupName)) {
            $outputtext = "Case2Deletion: Error Entra ID Exclusion Group does not contain Device anymore."
        }
    }
}

# Check if everything worked
if ($outputtext) {
    $outputtext = "FINAL CHECK: Error $outputtext"
}
else {
    $outputtext = "FINAL CHECK: SUCCESS"
}

Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body       = $outputtext
    })