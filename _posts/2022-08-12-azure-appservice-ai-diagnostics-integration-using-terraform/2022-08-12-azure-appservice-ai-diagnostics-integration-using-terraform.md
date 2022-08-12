---
layout: post
title:  "Integrating Azure App Service Application Insights with App Service Diagnostics using Terraform"
date:   2022-08-12 09:56:45 -0500
categories: azure appservice diagnostics
---

There is good post [here](https://azure.github.io/AppService/2020/04/21/Announcing-Application-Insights-Integration-with-App-Service-Diagnostics.html) on the Azure App Service team blog that discusses the integration between [Application Insights](https://docs.microsoft.com/en-us/azure/azure-monitor/app/app-insights-overview) and App Service Diagnostics, but a high-level description of the scenario is that Application Insights can be integrated into [App Service Diagnostics](https://docs.microsoft.com/en-us/azure/app-service/overview-diagnostics) to enable more effective troubleshooting and debugging.

The integration is easy to setup through the Azure portal. Navigate to any App Service and click the _Diagnose and solve problems_ menu item from the left menu.

![diagnose-and-solve-problems](/assets/images/posts/2022-08-12-azure-appservice-ai-diagnostics-integration-using-terraform/diagnose-and-solve-problems.png)

On the _Diagnose and solve problems_ page, click the _Availability and Performance_ tile.

![availability-and-performance](/assets/images/posts/2022-08-12-azure-appservice-ai-diagnostics-integration-using-terraform/availability-and-performance.png)

On the _Availability and Performance_ page, there is a button to click that will connect Application Insights to App Service Diagnostics.

![ai-asd-connect](/assets/images/posts/2022-08-12-azure-appservice-ai-diagnostics-integration-using-terraform/ai-asd-connect.png)

Easy, right? But what if you want this connection to be made by your IaC and your IaC language is Terraform? Read on.

### How is the integration made?

The [post]((https://azure.github.io/AppService/2020/04/21/Announcing-Application-Insights-Integration-with-App-Service-Diagnostics.html)) from the Azure App Service team blog is very clear on how the integration is made. I'll copy the same information here, just in case that blog post disappears or moves, but all credit for this detail goes to the Azure App Service team.

When you click Connect, an API key for your Application Insights is generated with read-only access to the telemetry and this API key along with the AppId for the Application Insights resource are stored as a hidden tag in ARM at the Azure App Service app level. At the App Insights Resource level, you may see something like this.

![appinsights-apikey](/assets/images/posts/2022-08-12-azure-appservice-ai-diagnostics-integration-using-terraform/appinsights-apikey.png)

On the App Services side, you should see a new tag created at the app level with the name hidden-related:diagnostics/applicationInsightsSettings. You can view this tag by going to Azure Resource Explorer (https://resources.azure.com). The AppId is stored as is, but the API Key is encrypted using an internal key, so it is kept protected and not left as clear text.

Using this information, App Services Diagnostics can query the Application Insights resource and is able to merge both the experiences together. For Microsoft support and engineering teams, an equivalent internal tool is available and engineers and engineering teams assisting you on your incidents opened with Microsoft can access this information in similar unified troubleshooting experience.

### Getting Terraform to do this integration

There is no native support in Terraform to make this integration, so we need to use other methods. Additionally, as noted in the Azure App Services team blog, the API Key is encrypted. It may seem a simple matter to just use the Terraform [azurerm_application_insights_api_key](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/application_insights_api_key) AzureRM provider resource to create the API Key and then stuff that into the hidden tag on the App Service. Unfortunately, that will not work as the API Key needs to be encrypted in a specifc way for this to work.

At a high-level, the steps that need to be performed to setup the integration are:

1. Create Application Insights Instance API Key
2. Encrypt the API Key
3. Add the hidden tag that includes the encrypted API Key to an App Service

Following are required pre-requisites that will not be covered here since they are straightforward steps using native Terraform resources.

- Powershell (v6+ - pwsh.exe)
- [A Resource Group](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/resource_group)
- [An Application Insights instance](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/application_insights)
- [An App Service Plan](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service_plan)

#### Create Application Insights Instance API Key

This step is easily accomplished using the native Terraform [azurerm_application_insights_api_key](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/application_insights_api_key) resource.

```text
# application insights api key for app service diagnostics
resource "azurerm_application_insights_api_key" "read_telemetry" {
  name                    = "APPSERVICEDIAGNOSTICS_READONLYKEY_${local.app_service_name}"
  application_insights_id = azurerm_application_insights.application_insights.id
  read_permissions        = ["agentconfig", "aggregate", "api", "draft", "extendqueries", "search"]
}
````

The name of the App Service is used in the API Key name just to make it clear what it is used for when inspecting the API Keys in Application Insights, but the name can be anything.

The Application Insights Id is from an Application Insights instance that is part of the pre-requisite for this process.

#### Encrypt the API Key

When App Service Diagnostics uses the API Key to query Application Insights data, the key is expected to be encrypted and that encryption must follow Microsoft's encryption algorithm. The encrypted key will be decrypted internally using Microsoft's encryption algorithm so if it is not encrypted at all, or not encrypted using Microsoft's encryption algorithm, the decryption will fail and the intergration will not succeed.

The only way I have found to encrypt the API Key using Microsoft's algorithm is to use a REST service provided by Microsoft specifically for encrypting the Application Insights API Key. This REST service requires authentication, so there are multiple steps we need to take to encrypt the API Key.

**Get a bearer token for authorization on the REST service**

To call the REST service for encrypting the API Key, we need to provide a bearer token. In this example, a service principal has been provisioned in Azure Active Directory for Terraform execution so we'll get the token from that service principal.

There is no native Terraform method to do this, so a [null resource](https://registry.terraform.io/providers/hashicorp/null/latest/docs/resources/resource) is used to run Powershell commands that will get the token.

````powershell
# get token for service principal so we can use the token in the rest call to the azure encryption engine
resource "null_resource" "application_insights_app_service_diagnostics" {
  provisioner "local-exec" {
    command = <<EOT
            $password = ConvertTo-SecureString -String $env:ARM_CLIENT_SECRET -AsPlainText -Force
            $Credential = New-Object -TypeName System.Management.Automation.PSCredential ($env:ARM_CLIENT_ID, $password)
            Connect-AzAccount -ServicePrincipal -TenantId $env:ARM_TENANT_ID -Credential $Credential

            $token = Get-AzAccessToken
            $token.Token | Out-File '${path.root}/token.txt'
        EOT

    interpreter = [
      "pwsh",
      "-Command"
    ]
  }
}
````

Note that there are some environment variable requirements with this script. Sensitive values like client secrets should not be part of source code, so those values are defined in environment variables and can be specific to each user when running these scripts manually. The following environment variables are required to run this resource:

1. **ARM_CLIENT_ID** - Azure Active Directory application (client) identifier for a service principal with appropriate permissions
2. **ARM_CLIENT_SECRET** - Client secret (password) from the ARM_CLIENT_ID
3. **ARM_TENANT_ID** - The identifier for the tenant that this script is running against

When the null_resource is executed, the token from the service principal is retrieved and stored in a local file. Storing the token in a local file could possibly present a security risk, but that is the best way I've found to get the token and make it available for later pieces of code in this process. There may be better ways.

**Call the REST service to encrypt the API Key**

Now that we have a bearer token, we can call the REST service that will encrypt the API Key. We will use a Terraform [local_file](https://registry.terraform.io/providers/hashicorp/local/latest/docs/resources/file) resource to retrieve the token from the token file created in the previous step and then use an [HTTP](https://registry.terraform.io/providers/hashicorp/http/latest/docs/data-sources/http) data source to make the call to the encryption service.

````text
# access to the token file
data "local_file" "token" {
  filename = "${path.root}/token.txt"

  depends_on = [
    null_resource.application_insights_app_service_diagnostics
  ]
}

# encrypt the api key
data "http" "encrypted_ai_api_key" {
  url = "https://appservice-diagnostics.azurefd.net/api/appinsights/encryptkey"

  request_headers = {
    Authorization   = "Bearer ${data.local_file.token.content_base64}"
    Accept          = "application/json"
    appinsights-key = "${azurerm_application_insights_api_key.read_telemetry.api_key}"
  }
}
````

**Add hidden tag to App Service**

The final step is to add the hidden tag that includes the encrypted API Key for Application Insights to the App Service.

````text
# app service
resource "azurerm_app_service" "app_service" {
  app_service_plan_id = azurerm_app_service_plan.example.id
  https_only          = true
  location            = azurerm_resource_group.example.location
  name                = local.app_service_name
  resource_group_name = azurerm_resource_group.example.name

  # combine the hidden tag necessary to connect app insights to app service diagnostics
  # with any that are passed in to end up with one set of tags for the app service
  tags = merge(
    local.tags,
    {
      "hidden-related:diagnostics/applicationInsightsSettings" = "{\"ApiKey\":${data.http.encrypted_ai_api_key.body},\"AppId\":\"${azurerm_application_insights.application_insights.app_id}\"}"
    }
  )
}
````

Since the hidden tag is likely not the only tag that is going to be added to the App Service, this code merges a local definition of tags with the hidden tag. Tags could also be passed in as a variable. The point here is that the merge operation will allow this code to take into account other tags along with the hidden tag.

### Verification

After this code is executed, follow the navigation instructions at the top of this post to get to the location where the integration is displayed in the Azure portal. Once you get there, you should see this:

![ai-asd-connected](/assets/images/posts/2022-08-12-azure-appservice-ai-diagnostics-integration-using-terraform/ai-asd-connected.png)