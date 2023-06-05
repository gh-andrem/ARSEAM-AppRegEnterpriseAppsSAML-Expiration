# M365 AppRegistration and SAML Enterprise Aplication Expiration Monitor (ARSEAM)

With an abundance of app registrations, enterprise applications and related client secrets, certificates and SAML/SSO certificates in an Azure AD tenant it becomes incredibly important to get notified well before they expire.
This solution also helps locating no longer or obsolete app registrations and enterprise applications.
This solution uses a managed identity for the Azure Automation account to authenticate against the tenant. It sends the collected information via Log Analytics to create an alert in Azure Monitor or Azure Sentinel (or any other SIEM) solution.

Credit goes to https://github.com/Cj-Scott/Get-AppRegistrationExpiration for initial solution.
