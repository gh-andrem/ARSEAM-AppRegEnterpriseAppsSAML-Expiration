# M365 AppRegistration and SAML Enterprise Aplication Expiration Monitor (ARSEAM)

With an abundance of app registrations, enterprise applications and related client secrets, certificates and SAML/SSO certificates in an Azure AD tenant it becomes incredibly important to get notified well before they expire.

This solution uses a managed identity in an Azure Automation account to authenticate against an M365 tenant. It sends the collected information via Log Analytics to create an alert in Azure Monitor or Microsoft Sentinel solution.
This solution also helps to locate no longer or obsolete app registrations and enterprise applications.

Credit goes to https://github.com/Cj-Scott/Get-AppRegistrationExpiration for initial solution.
