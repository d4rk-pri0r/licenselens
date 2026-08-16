# Security License Lens report

A plain-language view of security capabilities you already pay for — and whether they are set up to help your organization.

- **Version:** 0.4.0
- **Scanned at:** 2026-08-13T00:00:00+00:00
- **Mode:** dry_run / dry_run
- **Organization:** Contoso Demo (dry-run)

## At a glance

**5 of 6 still not fully working.**

- **Licensed capabilities detected:** 25
- **Prioritized capabilities:** 6 (priority packs: identity, endpoint)
- **Fully working:** 1 of 6 prioritized capabilities (17% realized)
- **Need attention:** 5 of 6 prioritized capabilities

### Top things to do first

1. **Restrict user consent so only admins approve non-trivial permissions** *(~a few hours)* — Users can still approve app permissions themselves, which is a common path for consent phishing.
   - Next step: Restrict user consent so only admins approve non-trivial permissions.
2. **Disable SMS, Voice, and Email OTP authentication methods** *(~a few hours)* — SMS, voice, or email one-time codes are still allowed — these are the easiest multi-factor methods for attackers to abuse.
   - Next step: Disable SMS, Voice, and Email OTP authentication methods.
3. **Enforce a Conditional Access policy that blocks device code flow** *(~a few hours)* — Device-code phishing can still complete a successful sign-in.
   - Next step: Enforce a Conditional Access policy that blocks device code flow.

*Effort is a rough guide, not a quote.*

- **Needs attention** (`gap`): 40
- **Not in your plan** (`not_licensed`): 3
- **Looking good** (`ok`): 71
- **Partly set up** (`partial`): 12
- **Check pending** (`skipped`): 14

## What you already pay for

### Smarter sign-in rules

*Microsoft name: Conditional Access*

- **What it does:** Decide who can sign in, from where, on which devices, and whether they must prove it is really them (for example with multi-factor authentication).
- **Why it matters:** Passwords alone are not enough. Good sign-in rules stop many everyday account takeovers before damage is done.
- **If unused:** Your licenses include advanced sign-in rules, but they may still be loose or incomplete.
- **Included through license SKU(s):** SPE_E5
- **Matching service plan(s):** AAD_PREMIUM_P2

### Deep protection and visibility on PCs and devices

*Microsoft name: Microsoft Defender for Endpoint P2*

- **What it does:** See attacks on laptops and servers in more detail, find weak software, and respond before a single infected PC becomes a company-wide problem.
- **Why it matters:** Devices are where people work. If they are not enrolled in advanced protection, you are flying partly blind.
- **If unused:** You may be paying for advanced device protection on seats that are not fully enrolled.
- **Included through license SKU(s):** SPE_E5
- **Matching service plan(s):** DEFENDER_ENDPOINT_P2

### Watchdogs on your on-site directory (if you still have one)

*Microsoft name: Microsoft Defender for Identity*

- **What it does:** Spot attackers moving through traditional office servers and Active Directory, not only cloud sign-ins.
- **Why it matters:** Many organizations still rely on on-site domain controllers. Cloud-only tools cannot see every attack path there.
- **If unused:** Identity threat sensors may be missing or unhealthy, so on-site directory attacks stay invisible.
- **Included through license SKU(s):** SPE_E5
- **Matching service plan(s):** No matching service plan reported

### Safe Attachments and Safe Links essentials

*Microsoft name: Microsoft Defender for Office 365 P1*

- **What it does:** Detonate risky attachments and rewrite dangerous links for licensed users even when the full P2 investigation pack is not present.
- **Why it matters:** Many tenants own P1-level email protections that never leave default off states.
- **If unused:** Safe content policies may be missing, scoped to pilots, or left in evaluation mode.
- **Included through license SKU(s):** SPE_E5
- **Matching service plan(s):** No matching service plan reported

### Stronger email and file threat protection

*Microsoft name: Microsoft Defender for Office 365 P2*

- **What it does:** Open risky attachments and links in a safe way, catch advanced phishing, and investigate email threats faster when something slips through.
- **Why it matters:** Most business breaches still start with email. Better email protection reduces ransomware and invoice fraud.
- **If unused:** Extra email protections in your license may still be off, in test mode, or only covering a few people.
- **Included through license SKU(s):** SPE_E5
- **Matching service plan(s):** THREAT_INTELLIGENCE

### Cross-product incident correlation

*Microsoft name: Microsoft Defender XDR*

- **What it does:** Connect identity, email, endpoint, and cloud signals into incidents that show the full attack story instead of isolated alerts.
- **Why it matters:** Attackers hop products. Siloed alerts hide the path from phishing to privilege.
- **If unused:** XDR correlation may be licensed while automated investigation and response stay idle.
- **Included through license SKU(s):** SPE_E5
- **Matching service plan(s):** DEFENDER_ENDPOINT_P2, THREAT_INTELLIGENCE

### Stronger control over admin accounts

*Microsoft name: Microsoft Entra ID P2*

- **What it does:** Give people powerful admin rights only when they need them, and get better tools to catch risky sign-ins on high-value accounts.
- **Why it matters:** Admin accounts are the keys to your email, files, and business apps. If one is stolen, an attacker can look like a trusted employee.
- **If unused:** You are paying for stronger admin protections that are not fully turned on yet.
- **Included through license SKU(s):** SPE_E5
- **Matching service plan(s):** AAD_PREMIUM_P2

### Business email and calendar in the cloud

*Microsoft name: Exchange Online*

- **What it does:** Host mailboxes in Microsoft 365 and apply tenant email security and sharing controls that protect everyday business communication.
- **Why it matters:** Email remains a primary business channel and a primary attack path. Weak tenant defaults leave phishing and data exposure wide open.
- **If unused:** Mailboxes may be licensed while core protection and audit settings stay at weak defaults.
- **Included through license SKU(s):** SPE_E5
- **Matching service plan(s):** No matching service plan reported

### Baseline spam and malware filtering for email

*Microsoft name: Exchange Online Protection*

- **What it does:** Filter obvious junk and malware before it reaches inboxes, as the foundation under optional Defender for Office 365 controls.
- **Why it matters:** Without baseline filtering, every advanced email control sits on a weak floor.
- **If unused:** Core anti-spam or anti-malware policies may be off, overly permissive, or unmonitored.
- **Included through license SKU(s):** SPE_E5
- **Matching service plan(s):** No matching service plan reported

### Alerts when a sign-in looks suspicious

*Microsoft name: Microsoft Entra ID Protection*

- **What it does:** Automatically spot odd sign-in behavior (impossible travel, leaked passwords, unfamiliar locations) and require extra proof or block access.
- **Why it matters:** Attackers often use valid passwords. Risk detection helps catch the session even when the password was correct.
- **If unused:** Suspicious-sign-in protection is included in your plan but may not be enforcing anything yet.
- **Included through license SKU(s):** SPE_E5
- **Matching service plan(s):** AAD_PREMIUM_P2

### Manage and protect company devices and apps

*Microsoft name: Microsoft Intune*

- **What it does:** Require healthy devices, push secure settings, and protect work data on phones and PCs people already use.
- **Why it matters:** Unmanaged devices are a common path around strong cloud identity controls.
- **If unused:** Compliance or configuration profiles may be missing, unassigned, or never enforced.
- **Included through license SKU(s):** SPE_E5
- **Matching service plan(s):** No matching service plan reported

### The log store behind security analytics

*Microsoft name: Azure Log Analytics*

- **What it does:** Land security and operational logs in a workspace that detections and investigations can query.
- **Why it matters:** Sentinel without healthy log ingestion is an empty command center.
- **If unused:** Workspaces may exist while critical tables are missing, short-retained, or never connected.
- **Included through license SKU(s):** MICROSOFT_SENTINEL
- **Matching service plan(s):** No matching service plan reported

### A central security command center in the cloud

*Microsoft name: Microsoft Sentinel*

- **What it does:** Bring security signals together in one place, detect patterns humans miss, and automate parts of incident response.
- **Why it matters:** Without a place that correlates events, teams drown in alerts from many products and miss the story that ties them together.
- **If unused:** A security workspace may exist, but few detections or smart analytics are turned on.
- **Included through license SKU(s):** MICROSOFT_SENTINEL
- **Matching service plan(s):** MICROSOFT_SENTINEL

### Personal work files in the cloud

*Microsoft name: OneDrive for Business*

- **What it does:** Give people a private work drive while still enforcing sharing limits, device access, and retention expectations.
- **Why it matters:** Personal work drives often hold the same sensitive files as shared libraries.
- **If unused:** OneDrive sharing or sync controls may lag behind the SharePoint tenant baseline.
- **Included through license SKU(s):** SPE_E5
- **Matching service plan(s):** No matching service plan reported

### Shared interactive business reports

*Microsoft name: Power BI Pro*

- **What it does:** Publish and share interactive reports with colleagues under tenant-level export, sharing, and guest boundaries.
- **Why it matters:** BI content often contains concentrated business truth; loose sharing leaks strategy.
- **If unused:** Tenant sharing or export settings may still allow broader distribution than intended.
- **Included through license SKU(s):** SPE_E5
- **Matching service plan(s):** No matching service plan reported

### Low-code apps, flows, and environments

*Microsoft name: Microsoft Power Platform*

- **What it does:** Let teams build useful apps and automations inside governed environments with DLP and tenant isolation boundaries.
- **Why it matters:** Ungoverned makers can connect business data to personal connectors overnight.
- **If unused:** Environment creation, connector policies, or tenant isolation may still be wide open.
- **Included through license SKU(s):** SPE_E5
- **Matching service plan(s):** No matching service plan reported

### A searchable record of important activity

*Microsoft name: Microsoft Purview Audit*

- **What it does:** Reconstruct who did what across mail, files, and admin actions when something goes wrong.
- **Why it matters:** Without audit history, investigations stall and compliance questions go unanswered.
- **If unused:** Audit logging may be off, truncated, or never queried after an incident.
- **Included through license SKU(s):** SPE_E5
- **Matching service plan(s):** EQUIVIO_ANALYTICS

### Oversight for risky business communications

*Microsoft name: Microsoft Purview Communication Compliance*

- **What it does:** Detect harassment, threats, or sensitive-data sharing patterns in business conversations.
- **Why it matters:** Toxic or noncompliant communication creates legal and cultural risk that identity tools miss.
- **If unused:** Communication compliance may be entitled but never scoped to the channels that matter.
- **Included through license SKU(s):** SPE_E5
- **Matching service plan(s):** No matching service plan reported

### Guardrails so sensitive data is harder to leak

*Microsoft name: Microsoft Purview Data Loss Prevention*

- **What it does:** Warn or block people when they try to share credit cards, health data, or other sensitive information in the wrong place.
- **Why it matters:** Accidental oversharing is common. Guardrails protect customers and reduce regulatory and reputational harm.
- **If unused:** Data-protection rules may be missing or still in "test only" mode, so nothing is enforced yet.
- **Included through license SKU(s):** SPE_E5
- **Matching service plan(s):** MIP_S_CLP2

### Legal hold and investigation search

*Microsoft name: Microsoft Purview eDiscovery*

- **What it does:** Preserve and search relevant content when legal or investigative work demands it.
- **Why it matters:** Missing holds destroy evidence and create legal and regulatory exposure.
- **If unused:** eDiscovery tools may be licensed while no one can run a defensible case workflow.
- **Included through license SKU(s):** SPE_E5
- **Matching service plan(s):** EQUIVIO_ANALYTICS, LOCKBOX_ENTERPRISE

### Early warning for risky insider activity

*Microsoft name: Microsoft Purview Insider Risk Management*

- **What it does:** Spot patterns that suggest data theft, leak, or policy abuse by people who already have access.
- **Why it matters:** Trusted access is powerful. Without signals, insider incidents surface only after damage.
- **If unused:** Insider risk policies may be unlicensed in practice or never moved past trial defaults.
- **Included through license SKU(s):** SPE_E5
- **Matching service plan(s):** No matching service plan reported

### Retention rules that keep or remove content on schedule

*Microsoft name: Microsoft Purview Data Lifecycle Management*

- **What it does:** Keep content for legal or regulatory periods and remove it when it is no longer needed, reducing both evidence risk and storage cost.
- **Why it matters:** Retention protects evidence and reduces over-retention risk and storage cost.
- **If unused:** Retention policies may be absent, so content is either deleted too early or kept indefinitely without a defensible schedule.
- **Included through license SKU(s):** SPE_E5
- **Matching service plan(s):** No matching service plan reported

### Labels that classify and protect files and mail

*Microsoft name: Microsoft Purview Sensitivity Labels*

- **What it does:** Mark sensitive content and apply encryption or access limits that travel with the file.
- **Why it matters:** Classification without enforcement is a sticker; labels with protection change outcomes.
- **If unused:** Labels may exist but remain unpublished, unused, or never auto-applied.
- **Included through license SKU(s):** SPE_E5
- **Matching service plan(s):** MIP_S_CLP2

### Team sites and shared file libraries

*Microsoft name: SharePoint Online*

- **What it does:** Host shared libraries with clear external sharing boundaries and default link permissions that match how the business actually works.
- **Why it matters:** Over-broad sharing turns one mistaken link into a public data leak.
- **If unused:** Tenant sharing defaults may still allow anyone links or unmanaged access.
- **Included through license SKU(s):** SPE_E5
- **Matching service plan(s):** No matching service plan reported

### Chat, meetings, and teamwork hub

*Microsoft name: Microsoft Teams*

- **What it does:** Keep collaboration fast while controlling guests, anonymous join, apps, and recording exposure.
- **Why it matters:** Teams is where decisions and files move quickly — weak meeting or guest defaults become an easy side door.
- **If unused:** External access, lobby, or app policies may still favor convenience over control.
- **Included through license SKU(s):** SPE_E5
- **Matching service plan(s):** No matching service plan reported


## Where you may not be getting the full benefit

### Require strong sign-in for powerful admin roles

- **Status:** Needs attention
- **In plain English:** Admin accounts may still sign in with weaker multi-factor methods.
- **Suggested next step:** Enforce phishing-resistant MFA for Global Administrator and other highly privileged roles.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies)
- **Technical id:** `id-ca-phishing-resistant-privileged`

### Some paid device-management seats may not be enrolled

- **Status:** Needs attention
- **In plain English:** You appear to pay for device management on many seats, but few devices are enrolled.
- **Suggested next step:** Compare Intune licenses to enrolled devices and enroll the missing ones through the device management tools you already use.
- **Confidence:** High confidence
- **Data sources:** graph.deviceManagement, graph.subscribedSkus
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://endpoint.microsoft.com/#view/Microsoft_Intune_Devices/DevicesMenu/~/allDevices)
- **Technical id:** `endpoint-enrollment-coverage`

### Review apps with broad permissions for everyone

- **Status:** Needs attention
- **In plain English:** Some apps have broad mail, files, or directory permissions for everyone.
- **Suggested next step:** Review and remove high-impact AllPrincipals OAuth grants that are not required.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade)
- **Technical id:** `id-app-risky-delegated-consent`

### Stop users from approving risky app permissions

- **Status:** Needs attention
- **In plain English:** Users can still approve app permissions themselves, which is a common path for consent phishing.
- **Suggested next step:** Restrict user consent so only admins approve non-trivial permissions.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserSettingsMenuBlade)
- **Technical id:** `id-app-user-consent-restricted`

### Turn off SMS, voice, and email one-time codes

- **Status:** Needs attention
- **In plain English:** SMS, voice, or email one-time codes are still allowed — these are the easiest multi-factor methods for attackers to abuse.
- **Suggested next step:** Disable SMS, Voice, and Email OTP authentication methods.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade)
- **Technical id:** `id-auth-weak-methods-disabled`

### Block device-code phishing sign-ins

- **Status:** Needs attention
- **In plain English:** Device-code phishing can still complete a successful sign-in.
- **Suggested next step:** Enforce a Conditional Access policy that blocks device code flow.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies)
- **Technical id:** `id-ca-device-code-block`

### Block suspicious high-risk sign-ins

- **Status:** Needs attention
- **In plain English:** Suspicious high-risk sign-ins may still succeed.
- **Suggested next step:** Enforce a Conditional Access policy that blocks high sign-in risk.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies)
- **Technical id:** `id-ca-high-risk-signins`

### Block accounts Microsoft marks as high risk

- **Status:** Needs attention
- **In plain English:** Compromised accounts marked high risk may still sign in successfully.
- **Suggested next step:** Enforce a Conditional Access policy that blocks high user risk for all users.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies)
- **Technical id:** `id-ca-high-risk-users`

### Block outdated sign-in methods

- **Status:** Needs attention
- **In plain English:** Outdated sign-in methods may still work without multi-factor checks.
- **Suggested next step:** Create a Conditional Access policy that blocks legacy authentication for all users, with documented emergency-access exclusions only.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies)
- **Technical id:** `id-ca-legacy-auth-block`

### Require strong phishing-resistant sign-in for everyone

- **Status:** Needs attention
- **In plain English:** Users can still sign in with weaker multi-factor methods that phishing can defeat.
- **Suggested next step:** Enforce phishing-resistant authentication strength for all users where feasible.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies)
- **Technical id:** `id-ca-phishing-resistant-all`

### Alert when Global Admin is turned on

- **Status:** Needs attention
- **In plain English:** Global Admin can be activated without a clear alert path.
- **Suggested next step:** Enable notifications for Global Administrator activation.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://portal.azure.com/#view/Microsoft_Azure_PIMCommon/CommonMenuBlade/~/quickStart)
- **Technical id:** `id-pim-ga-activation-alert`

### Require approval to turn on Global Admin

- **Status:** Needs attention
- **In plain English:** Someone eligible for Global Admin can turn it on without a second approver.
- **Suggested next step:** Require approval on Global Administrator PIM activation.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://portal.azure.com/#view/Microsoft_Azure_PIMCommon/CommonMenuBlade/~/quickStart)
- **Technical id:** `id-pim-ga-activation-approval`

### Provision admin access only through just-in-time tools

- **Status:** Needs attention
- **In plain English:** Powerful admin access is granted permanently without a just-in-time system.
- **Suggested next step:** Stop direct permanent privileged assignments and route access through PIM.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://portal.azure.com/#view/Microsoft_Azure_PIMCommon/CommonMenuBlade/~/quickStart)
- **Technical id:** `id-pim-no-outside-pam`

### Remove always-on powerful admin assignments

- **Status:** Needs attention
- **In plain English:** Some powerful admin roles are permanently on instead of just-in-time.
- **Suggested next step:** Convert highly privileged standing assignments to PIM-eligible where possible.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://portal.azure.com/#view/Microsoft_Azure_PIMCommon/CommonMenuBlade/~/quickStart)
- **Technical id:** `id-pim-no-permanent-privileged`

### Admin accounts still have "always on" superpowers

- **Status:** Needs attention
- **In plain English:** Admin superpowers appear permanently on. Time-limited admin access (included in your stronger identity plan) does not look like it is being used.
- **Suggested next step:** Ask IT to turn on time-limited admin access for your top admins first (Global Administrator and similar roles).
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://portal.azure.com/#view/Microsoft_AAD_IAM/RoleAssignmentsBlade)
- **Technical id:** `id-pim-unused`

### Move from Security Defaults to customizable sign-in rules

- **Status:** Needs attention
- **In plain English:** Security Defaults already includes baseline MFA protection and blocks outdated sign-in methods. Your plan also includes smarter sign-in rules you can customize, but that paid capability remains unused.
- **Suggested next step:** Create equivalent Conditional Access policies for MFA and legacy-authentication blocking in report-only mode. Validate coverage, exclusions, emergency access, and sign-in impact; then perform a controlled cutover from Security Defaults to the validated policies.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ConditionalAccessBlade)
- **Technical id:** `id-security-defaults-on`

### Some PCs may not be enrolled in advanced device protection

- **Status:** Needs attention
- **In plain English:** You appear to pay for advanced device protection on many seats, but relatively few devices are enrolled.
- **Suggested next step:** Compare licensed seats to enrolled devices and enroll the missing ones (often through your device management tools).
- **Confidence:** High confidence
- **Data sources:** mde.api.machines, graph.subscribedSkus
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://security.microsoft.com/machines)
- **Technical id:** `mde-onboard-gap`

### Apply DLP across Exchange SharePoint OneDrive Teams

- **Status:** Needs attention
- **In plain English:** We could not find DLP policies covering your data locations.
- **Suggested next step:** Enable DLP for Exchange, OneDrive, SharePoint, Teams, and devices where licensed.
- **Confidence:** High confidence
- **Data sources:** scc_compliance
- **Limitations:** Per-location coverage is derived from policy workload flags, not a full location enumeration
- **Admin page:** [Open Microsoft admin page](https://compliance.microsoft.com/datalossprevention)
- **Technical id:** `pur-dlp-locations-complete`

### Turn on auto-labeling for sensitive content

- **Status:** Needs attention
- **In plain English:** Content must be labeled by hand. Configure auto-labeling so sensitive content is classified consistently.
- **Suggested next step:** Configure auto-labeling policies or default labels so new and existing content is classified automatically, then monitor the results.
- **Confidence:** High confidence
- **Data sources:** Microsoft Purview / Security & Compliance PowerShell (powershell.bridge)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://purview.microsoft.com/informationprotection/autolabeling)
- **Technical id:** `pur-sensitivity-auto-labeling`

### Set up periodic access reviews for admins and guests

- **Status:** Needs attention
- **In plain English:** Your plan can periodically confirm who still needs powerful access and clean up old guest accounts. That process does not look set up yet.
- **Suggested next step:** Create an Access Review for your Global Administrators and guest users (monthly or quarterly), then review the first round of results.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_ERM/DashboardBlade)
- **Technical id:** `id-access-reviews-unused`

### Block risky AI agents when the control is available

- **Status:** Needs attention
- **In plain English:** We did not find an automated block for risky AI agents. Confirm in Entra whether agent risk controls are available and enforced for your tenant.
- **Suggested next step:** Review Entra AI agent risk controls and enforce blocks where licensed and supported.
- **Confidence:** Low confidence — verify in portal
- **Data sources:** microsoft.graph
- **Limitations:** AI agent risk controls vary by cloud and license; treat this as advisory
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies)
- **Technical id:** `id-ai-agents-risky-block`

### Turn on admin approval requests for apps

- **Status:** Needs attention
- **In plain English:** There is no structured way for users to request admin approval for apps.
- **Suggested next step:** Enable the admin consent request workflow with monitored reviewers.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade)
- **Technical id:** `id-app-admin-consent-workflow`

### Rotate expiring app secrets and certificates

- **Status:** Needs attention
- **In plain English:** Some app secrets or certificates are expired or about to expire.
- **Suggested next step:** Rotate credentials expiring within 30 days and remove already-expired secrets.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade)
- **Technical id:** `id-app-expiring-credentials`

### Block legacy app passwords

- **Status:** Needs attention
- **In plain English:** Users may still create app passwords that skip modern multi-factor checks.
- **Suggested next step:** Block creation of app passwords with Conditional Access or authentication method controls.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies)
- **Technical id:** `id-app-password-addition-blocked`

### Stop regular users from creating apps

- **Status:** Needs attention
- **In plain English:** Anyone in the directory can create app registrations, which expands the attack surface for malicious apps.
- **Suggested next step:** Disable user application registration in Entra user settings.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserSettingsMenuBlade)
- **Technical id:** `id-app-registration-admin-only`

### Show app and location on Authenticator prompts

- **Status:** Needs attention
- **In plain English:** Authenticator prompts do not clearly show app and location context, which makes push phishing harder to spot.
- **Suggested next step:** Enable application name and geographic location in Microsoft Authenticator notifications.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade)
- **Technical id:** `id-auth-authenticator-context`

### Require company-managed devices for access

- **Status:** Needs attention
- **In plain English:** Users may access work apps from unmanaged personal devices.
- **Suggested next step:** Enforce Conditional Access requiring compliant or hybrid-joined devices.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies)
- **Technical id:** `id-ca-managed-devices`

### Only allow multi-factor setup from managed devices

- **Status:** Needs attention
- **In plain English:** Attackers with a stolen password may register their own multi-factor method.
- **Suggested next step:** Require a managed device when users register security information.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies)
- **Technical id:** `id-ca-mfa-registration-managed`

### Powerful accounts that nobody uses are still switched on

- **Status:** Needs attention
- **In plain English:** Some powerful accounts are still switched on but have not been used recently. Unused admin accounts and workload identities are a favorite target for attackers.
- **Suggested next step:** Review enabled admin accounts that have not signed in for a long time; disable or remove access you no longer need.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_IAM/SignInEventsBlade)
- **Technical id:** `id-dormant-privileged`

### Limit what guests can see in your directory

- **Status:** Needs attention
- **In plain English:** Guest accounts can see directory information similar to full members.
- **Suggested next step:** Set guest user access to limited or restricted in Entra external collaboration settings.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_IAM/CompanyRelationshipsMenuBlade)
- **Technical id:** `id-guest-directory-access-limited`

### Stop everyone from inviting external guests

- **Status:** Needs attention
- **In plain English:** Many users can invite external guests without a special role.
- **Suggested next step:** Allow only admins and Guest Inviter role holders to invite guests.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_IAM/CompanyRelationshipsMenuBlade)
- **Technical id:** `id-guest-inviter-restricted`

### Alert when powerful roles are assigned

- **Status:** Needs attention
- **In plain English:** Powerful role assignments may happen without an alert.
- **Suggested next step:** Enable PIM notifications for privileged role assignment events.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://portal.azure.com/#view/Microsoft_Azure_PIMCommon/CommonMenuBlade/~/quickStart)
- **Technical id:** `id-pim-privileged-assignment-alert`

### Guardrails against accidental data leaks may not be active

- **Status:** Needs attention
- **In plain English:** You appear to pay for data-leak protection that is not meaningfully enforced yet. Confirm in the Purview portal.
- **Suggested next step:** Start with a simple policy for email and cloud files that detects obvious sensitive data, then move from "test" to "enforce" after a short tuning period.
- **Confidence:** Low confidence — verify in portal
- **Data sources:** secureScore.controlScores (proxy)
- **Limitations:** Secure Score proxy — verify DLP enforce mode in Purview portal; Based on Microsoft Secure Score signals — confirm the real setting in the Microsoft 365 / security admin portal before treating this as definitive
- **Admin page:** [Open Microsoft admin page](https://purview.microsoft.com/policiespage)
- **Technical id:** `pur-dlp-not-enforced`

### Automate part of the incident response

- **Status:** Needs attention
- **In plain English:** Your security workspace reacts to nothing automatically — every alert waits for a person.
- **Suggested next step:** Add automation rules that trigger playbooks for common alerts, so response starts without waiting for a person.
- **Confidence:** Medium confidence
- **Data sources:** azure.arm.securityInsights
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://learn.microsoft.com/azure/sentinel/automate-responses-with-playbooks)
- **Technical id:** `sen-automation-rules`

### Keep security logs long enough to investigate

- **Status:** Needs attention
- **In plain English:** Security logs may be erased before investigations can complete.
- **Suggested next step:** Raise the workspace data retention to at least 90 days (and consider archive tiers for long-term storage).
- **Confidence:** Medium confidence
- **Data sources:** azure.arm.securityInsights
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://learn.microsoft.com/azure/azure-monitor/logs/data-retention-archive)
- **Technical id:** `sen-log-analytics-retention`

### Behavior-based detection may still be switched off

- **Status:** Needs attention
- **In plain English:** Behavior analytics that learn normal patterns for people and devices still looks switched off.
- **Suggested next step:** Ask your security admin to turn on behavior analytics (UEBA) in the security workspace and connect the main data sources it needs.
- **Confidence:** Medium confidence
- **Data sources:** azure.arm.securityInsights
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://learn.microsoft.com/azure/sentinel/enable-entity-behavior-analytics)
- **Technical id:** `sen-ueba-not-enabled`

### Stop live events from always recording

- **Status:** Needs attention
- **In plain English:** Live events always record. Let organizers choose or disable recording.
- **Suggested next step:** Set 'Record an event' to organizer can record or never record.
- **Confidence:** High confidence
- **Data sources:** Microsoft Teams / SharePoint Online PowerShell (powershell.bridge)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://admin.teams.microsoft.com)
- **Technical id:** `teams-broadcast-not-always-record`

### Restrict Microsoft apps to approved ones

- **Status:** Needs attention
- **In plain English:** Some users can install any Microsoft app. Restrict to approved apps.
- **Suggested next step:** Block all Microsoft apps or allow only approved ones.
- **Confidence:** Medium confidence
- **Data sources:** Microsoft Teams / SharePoint Online PowerShell (powershell.bridge)
- **Limitations:** Org-wide app settings (v2) were not readable; only legacy permission policies were evaluated
- **Admin page:** [Open Microsoft admin page](https://admin.teams.microsoft.com)
- **Technical id:** `teams-microsoft-apps-governed`

### Disable meeting recording by default

- **Status:** Needs attention
- **In plain English:** Recording is on for some users. Disable it unless explicitly required.
- **Suggested next step:** Turn off 'Meeting recording' unless a specific group needs it.
- **Confidence:** High confidence
- **Data sources:** Microsoft Teams / SharePoint Online PowerShell (powershell.bridge)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://admin.teams.microsoft.com)
- **Technical id:** `teams-recording-disabled`

### Stop calendar-based password expiration

- **Status:** Needs attention
- **In plain English:** Passwords still expire on a schedule. Modern guidance is to ban periodic expiration and use strong multi-factor authentication instead.
- **Suggested next step:** Set password validity to never expire on verified managed domains.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Domains)
- **Technical id:** `id-password-never-expire`

### Powerful accounts may sign in without strong extra checks

- **Status:** Partly set up
- **In plain English:** Some sign-in protections are present, but the full set is not enforced yet (multi-factor authentication and/or blocking outdated sign-in methods).
- **Suggested next step:** Require multi-factor authentication for admins and block legacy email sign-in methods that skip modern security prompts.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies)
- **Technical id:** `id-ca-priv-gaps`

### Some device-protection sensors may be inactive or unhealthy

- **Status:** Partly set up
- **In plain English:** A few device-protection sensors look unhealthy and may be missing alerts.
- **Suggested next step:** Review inactive and unhealthy sensors and remediate them (reinstall, connectivity, or policy) so every licensed device reports health.
- **Confidence:** High confidence
- **Data sources:** mde.api.machines.health
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://security.microsoft.com/machines)
- **Technical id:** `mde-sensor-health`

### Your security command center may have few alarms turned on

- **Status:** Partly set up
- **In plain English:** Some detection alarms are on, but coverage still looks light for a paid security command center.
- **Suggested next step:** Enable a starter set of detection rules for sign-ins, email, and devices, then expand coverage with your IT or security partner.
- **Confidence:** Medium confidence
- **Data sources:** azure.arm.securityInsights
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://learn.microsoft.com/azure/sentinel/detect-threats-built-in)
- **Technical id:** `sen-analytics-rule-coverage`

### Feed your security command center with real signals

- **Status:** Partly set up
- **In plain English:** A few data sources are connected, but the main identity and Microsoft 365 signals may still be missing.
- **Suggested next step:** Connect the main data sources (Entra ID, Microsoft 365, and Defender) to the security workspace, then confirm logs start arriving.
- **Confidence:** Medium confidence
- **Data sources:** azure.arm.securityInsights
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://learn.microsoft.com/azure/sentinel/connect-data-sources)
- **Technical id:** `sen-data-connectors`

### Clean up abandoned apps

- **Status:** Partly set up
- **In plain English:** Some apps have no owner or look abandoned, which makes secret and permission cleanup harder.
- **Suggested next step:** Assign owners to critical apps and remove abandoned registrations.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade)
- **Technical id:** `id-app-ownerless-or-stale`

### Finish consolidating sign-in method settings

- **Status:** Partly set up
- **In plain English:** Your organization started consolidating sign-in methods but has not finished.
- **Suggested next step:** Complete authentication methods migration to Migration Complete.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade)
- **Technical id:** `id-auth-methods-migration`

### Tighten default access from unknown external tenants

- **Status:** Partly set up
- **In plain English:** External tenants can collaborate by default — tighten this unless partner allowlists are intentional.
- **Suggested next step:** Review and tighten default cross-tenant access settings.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_IAM/CompanyRelationshipsMenuBlade)
- **Technical id:** `id-cross-tenant-defaults`

### Use narrower admin roles instead of Global Admin

- **Status:** Partly set up
- **In plain English:** Some finer-grained admin roles exist, but Global Admin may still be overused.
- **Suggested next step:** Move routine admin duties to finer-grained directory roles and keep Global Admin rare.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://portal.azure.com/#view/Microsoft_Azure_PIMCommon/CommonMenuBlade/~/quickStart)
- **Technical id:** `id-ga-finer-roles`

### Alert when other powerful admin roles activate

- **Status:** Partly set up
- **In plain English:** Confirm alerts fire when other admin roles are activated.
- **Suggested next step:** Enable PIM activation notifications for other highly privileged roles.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://portal.azure.com/#view/Microsoft_Azure_PIMCommon/CommonMenuBlade/~/quickStart)
- **Technical id:** `id-pim-other-activation-alert`

### On-site directory servers may lack attack sensors

- **Status:** Partly set up
- **In plain English:** We could not confirm whether on-site directory attack sensors are installed. If you still run office domain controllers, ask IT to verify.
- **Suggested next step:** Confirm whether you still use on-site directory servers; if yes, install and health-check the identity sensors on each one.
- **Confidence:** Low confidence — verify in portal
- **Data sources:** secureScore.controlScores (proxy)
- **Limitations:** Secure Score proxy — verify MDI sensors in the Defender portal; Based on Microsoft Secure Score signals — confirm the real setting in the Microsoft 365 / security admin portal before treating this as definitive
- **Admin page:** [Open Microsoft admin page](https://security.microsoft.com/health)
- **Technical id:** `mdi-sensors-missing`

### Restrict custom apps to approved ones

- **Status:** Partly set up
- **In plain English:** Custom apps are governed by policy Org-wide app settings could not be confirmed automatically.
- **Suggested next step:** Block all custom apps or allow only approved ones.
- **Confidence:** Medium confidence
- **Data sources:** Microsoft Teams / SharePoint Online PowerShell (powershell.bridge)
- **Limitations:** Org-wide app settings (v2) were not readable; only legacy permission policies were evaluated
- **Admin page:** [Open Microsoft admin page](https://admin.teams.microsoft.com)
- **Technical id:** `teams-custom-apps-governed`

### Restrict third-party apps to approved ones

- **Status:** Partly set up
- **In plain English:** Third-party apps are governed by policy Org-wide app settings could not be confirmed automatically.
- **Suggested next step:** Block all third-party apps or allow only approved ones.
- **Confidence:** Medium confidence
- **Data sources:** Microsoft Teams / SharePoint Online PowerShell (powershell.bridge)
- **Limitations:** Org-wide app settings (v2) were not readable; only legacy permission policies were evaluated
- **Admin page:** [Open Microsoft admin page](https://admin.teams.microsoft.com)
- **Technical id:** `teams-third-party-apps-governed`

### Add your mailbox to DMARC reports

- **Status:** Check pending
- **In plain English:** Provide the contact in your profile to check this DMARC field.
- **Suggested next step:** Add an internal rua/ruf contact from your assessment profile to DMARC.
- **Confidence:** Low confidence — verify in portal
- **Data sources:** Not reported
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://admin.microsoft.com/#/Domains)
- **Technical id:** `exo-dmarc-agency-contact`

### Add the federal DMARC report mailbox when required

- **Status:** Check pending
- **In plain English:** Provide the contact in your profile to check this DMARC field.
- **Suggested next step:** When your profile sets a federal contact, include it in every DMARC rua field.
- **Confidence:** Low confidence — verify in portal
- **Data sources:** Not reported
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://admin.microsoft.com/#/Domains)
- **Technical id:** `exo-dmarc-federal-contact`

### Confirm identity logs reach your security team

- **Status:** Check pending
- **In plain English:** Confirm Entra sign-in and audit logs reach your security monitoring platform.
- **Suggested next step:** Confirm Entra sign-in and audit logs are exported to your SOC or SIEM.
- **Confidence:** Low confidence — verify in portal
- **Data sources:** microsoft.graph
- **Limitations:** Manual verification required with your SOC / SIEM team
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_IAM/DiagnosticSettingsMenuBlade)
- **Technical id:** `id-logs-to-soc`

### Confirm suspicious-email alerts are enabled

- **Status:** Check pending
- **In plain English:** Confirm required suspicious-email and connector alerts are enabled.
- **Suggested next step:** Enable the required suspicious email and connector alert policies in Defender.
- **Confidence:** Low confidence — verify in portal
- **Data sources:** Not reported
- **Limitations:** Manual verification required in Microsoft 365 Defender alert policies
- **Admin page:** [Open Microsoft admin page](https://security.microsoft.com/alertpoliciesv2)
- **Technical id:** `mdo-alert-policies-enabled`

### Confirm audit logs are retained long enough

- **Status:** Check pending
- **In plain English:** Confirm audit logs stay searchable 3 months and retrievable 12 months.
- **Suggested next step:** Confirm at least 3 months searchable and 12 months retrievable audit retention.
- **Confidence:** Low confidence — verify in portal
- **Data sources:** Not reported
- **Limitations:** Manual verification required for audit log retention
- **Admin page:** [Open Microsoft admin page](https://compliance.microsoft.com/auditlogsearch)
- **Technical id:** `mdo-audit-retention`

### Protect key partner domains from look-alikes

- **Status:** Check pending
- **In plain English:** List your key partner domains in the profile to check their impersonation protection.
- **Suggested next step:** Enable targeted domain protection for profile-listed partner domains.
- **Confidence:** Low confidence — verify in portal
- **Data sources:** Not reported
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://security.microsoft.com/antiphishing)
- **Technical id:** `mdo-impersonation-partner-domains`

### Protect sensitive accounts from look-alike senders

- **Status:** Check pending
- **In plain English:** List your high-value accounts (executives, admins) in the profile to check user impersonation protection.
- **Suggested next step:** Enable user impersonation protection for profile-listed sensitive accounts.
- **Confidence:** Low confidence — verify in portal
- **Data sources:** Not reported
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://security.microsoft.com/antiphishing)
- **Technical id:** `mdo-impersonation-users-protected`

### Confirm insider risk management is set up

- **Status:** Check pending
- **In plain English:** Confirm an insider risk policy is created, scoped, and analytics is enabled.
- **Suggested next step:** Confirm an insider risk policy is created, scoped to the right users, and analytics is enabled in the Purview portal.
- **Confidence:** Low confidence — verify in portal
- **Data sources:** Not reported
- **Limitations:** Manual verification required in Microsoft Purview Insider Risk Management
- **Admin page:** [Open Microsoft admin page](https://purview.microsoft.com/insiderriskmgmt)
- **Technical id:** `pur-insider-risk-readiness`

### Make anyone links expire within 30 days

- **Status:** Check pending
- **In plain English:** Anyone links are disabled, so link expiration is not required.
- **Suggested next step:** Require anyone links to expire within 30 days.
- **Confidence:** Low confidence — verify in portal
- **Data sources:** Not reported
- **Limitations:** Anyone links are disabled, so link expiration is not required
- **Admin page:** [Open Microsoft admin page](https://admin.microsoft.com/sharepoint)
- **Technical id:** `spo-anyone-link-expiration`

### Make anyone links view-only

- **Status:** Check pending
- **In plain English:** Anyone links are disabled, so link permissions are not required.
- **Suggested next step:** Restrict anyone links to view-only for files and folders.
- **Confidence:** Low confidence — verify in portal
- **Data sources:** Not reported
- **Limitations:** Anyone links are disabled, so link permissions are not required
- **Admin page:** [Open Microsoft admin page](https://admin.microsoft.com/sharepoint)
- **Technical id:** `spo-anyone-link-view`

### Limit guest invites to approved partner domains

- **Status:** Check pending
- **In plain English:** We cannot judge guest invite domains until your organization lists approved partner domains in the assessment profile.
- **Suggested next step:** List approved partner domains in the assessment profile and mirror them in Entra B2B allowlists.
- **Confidence:** Low confidence — verify in portal
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_IAM/CompanyRelationshipsMenuBlade)
- **Technical id:** `id-guest-invite-domains`

### Confirm high-risk account alerts reach security

- **Status:** Check pending
- **In plain English:** Ask IT to confirm Identity Protection emails high-risk user alerts to a monitored security mailbox.
- **Suggested next step:** In Identity Protection, send high-risk user alerts to a monitored security mailbox.
- **Confidence:** Low confidence — verify in portal
- **Data sources:** microsoft.graph
- **Limitations:** Manual verification required in Microsoft Entra ID Protection notifications
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_IAM/IdentityProtectionMenuBlade)
- **Technical id:** `id-idprotect-notify-high-risk`

### Confirm communication compliance is set up

- **Status:** Check pending
- **In plain English:** Confirm communication compliance policies cover the channels that matter.
- **Suggested next step:** Confirm communication compliance policies cover the channels that matter and route matches to the right reviewers in the Purview portal.
- **Confidence:** Low confidence — verify in portal
- **Data sources:** Not reported
- **Limitations:** Manual verification required in Microsoft Purview Communication Compliance
- **Admin page:** [Open Microsoft admin page](https://purview.microsoft.com/communicationcompliance)
- **Technical id:** `pur-communication-compliance-readiness`

### Confirm eDiscovery is set up

- **Status:** Check pending
- **In plain English:** Confirm eDiscovery administrators and hold workflows are configured.
- **Suggested next step:** Confirm eDiscovery administrators are assigned and legal hold workflows are configured in the Purview portal.
- **Confidence:** Low confidence — verify in portal
- **Data sources:** Not reported
- **Limitations:** Manual verification required in Microsoft Purview eDiscovery
- **Admin page:** [Open Microsoft admin page](https://purview.microsoft.com/ediscovery)
- **Technical id:** `pur-ediscovery-readiness`

### Device compliance rules may be missing or not assigned

- **Status:** Looking good
- **In plain English:** Device compliance policies are defined and assigned.
- **Suggested next step:** Confirm compliance policies exist and are assigned to the right user or device groups, and that every managed device platform is covered.
- **Confidence:** High confidence
- **Data sources:** graph.deviceManagement
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://endpoint.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesComplianceMenu/~/policies)
- **Technical id:** `endpoint-compliance-policy-assigned`

### Devices may not be flowing into advanced protection

- **Status:** Looking good
- **In plain English:** Devices are flowing from Intune into Defender for Endpoint.
- **Suggested next step:** Enable the Intune to Defender for Endpoint connector and confirm devices appear onboarded.
- **Confidence:** High confidence
- **Data sources:** graph.deviceManagement
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://security.microsoft.com/securitysettings/endpoints/integration)
- **Technical id:** `endpoint-mde-connector`

### Core endpoint protections may be partially configured

- **Status:** Looking good
- **In plain English:** Core endpoint protections are configured for managed devices.
- **Suggested next step:** Confirm endpoint-security policies exist for antivirus, firewall, disk encryption, and attack surface reduction, and that they are assigned.
- **Confidence:** High confidence
- **Data sources:** graph.deviceManagement
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://endpoint.microsoft.com/#view/Microsoft_Intune_Workflows/SecurityManagementMenu/~/overview)
- **Technical id:** `endpoint-security-policy-coverage`

### Turn on DKIM signing for every domain

- **Status:** Looking good
- **In plain English:** Your domains sign outgoing mail with DKIM.
- **Suggested next step:** Enable DKIM signing for each accepted domain in Defender.
- **Confidence:** High confidence
- **Data sources:** Exchange Online PowerShell (powershell.bridge), Security & Compliance PowerShell (scc_compliance)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://security.microsoft.com/authentication?viewid=DKIM)
- **Technical id:** `exo-dkim-enabled`

### Publish a DMARC record for every domain

- **Status:** Looking good
- **In plain English:** Your domains publish DMARC records.
- **Suggested next step:** Publish a DMARC TXT record at _dmarc for each second-level domain.
- **Confidence:** High confidence
- **Data sources:** DNS TXT resolution (system resolver)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://admin.microsoft.com/#/Domains)
- **Technical id:** `exo-dmarc-published`

### Set DMARC policy to reject

- **Status:** Looking good
- **In plain English:** Your domains reject mail that fails authentication.
- **Suggested next step:** Set p=reject on every domain DMARC record.
- **Confidence:** High confidence
- **Data sources:** DNS TXT resolution (system resolver)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://admin.microsoft.com/#/Domains)
- **Technical id:** `exo-dmarc-reject`

### Flag mail that comes from outside

- **Status:** Looking good
- **In plain English:** Users see a clear flag when mail comes from outside your organization.
- **Suggested next step:** Enable external sender mail tips or an [External] transport rule.
- **Confidence:** High confidence
- **Data sources:** Exchange Online PowerShell (powershell.bridge), Security & Compliance PowerShell (scc_compliance)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://admin.exchange.microsoft.com/#/transportrules)
- **Technical id:** `exo-external-sender-warnings`

### Stop automatic email forwarding to outside domains

- **Status:** Looking good
- **In plain English:** External mail forwarding is locked down.
- **Suggested next step:** Disable automatic forwarding on remote domains except approved partners.
- **Confidence:** High confidence
- **Data sources:** Exchange Online PowerShell (powershell.bridge), Security & Compliance PowerShell (scc_compliance)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://admin.exchange.microsoft.com/#/remotedomains)
- **Technical id:** `exo-forwarding-external-disabled`

### Keep mailbox auditing turned on

- **Status:** Looking good
- **In plain English:** Mailbox access is being recorded for later investigation.
- **Suggested next step:** Ensure organization mailbox auditing is enabled (AuditDisabled false).
- **Confidence:** High confidence
- **Data sources:** Exchange Online PowerShell (powershell.bridge), Security & Compliance PowerShell (scc_compliance)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://admin.exchange.microsoft.com/)
- **Technical id:** `exo-mailbox-audit-enabled`

### Limit calendar sharing to approved domains

- **Status:** Looking good
- **In plain English:** Calendar sharing is limited to approved domains.
- **Suggested next step:** Remove sharing-with-all-domains from calendar sharing policies.
- **Confidence:** High confidence
- **Data sources:** Exchange Online PowerShell (powershell.bridge), Security & Compliance PowerShell (scc_compliance)
- **Limitations:** Calendar free/busy vs full-detail sharing granularity is not distinguished
- **Admin page:** [Open Microsoft admin page](https://admin.exchange.microsoft.com/#/individualsharing)
- **Technical id:** `exo-sharing-calendar-not-all-domains`

### Limit contact sharing to approved domains

- **Status:** Looking good
- **In plain English:** Contact folder sharing is limited to approved domains.
- **Suggested next step:** Remove sharing-with-all-domains from contact sharing policies.
- **Confidence:** High confidence
- **Data sources:** Exchange Online PowerShell (powershell.bridge), Security & Compliance PowerShell (scc_compliance)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://admin.exchange.microsoft.com/#/individualsharing)
- **Technical id:** `exo-sharing-contact-not-all-domains`

### Turn off SMTP AUTH for the organization

- **Status:** Looking good
- **In plain English:** Legacy basic-auth email submission is turned off.
- **Suggested next step:** Disable SMTP AUTH at the organization level unless a legacy app truly needs it.
- **Confidence:** High confidence
- **Data sources:** Exchange Online PowerShell (powershell.bridge), Security & Compliance PowerShell (scc_compliance)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://admin.exchange.microsoft.com/#/settings)
- **Technical id:** `exo-smtp-auth-disabled`

### Publish a strict SPF record for every domain

- **Status:** Looking good
- **In plain English:** Your domains publish strict SPF records.
- **Suggested next step:** Publish SPF TXT records that end in -all or ~all for each custom domain.
- **Confidence:** High confidence
- **Data sources:** DNS TXT resolution (system resolver)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://admin.microsoft.com/#/Domains)
- **Technical id:** `exo-spf-published`

### Require multi-factor authentication for everyone

- **Status:** Looking good
- **In plain English:** Everyone must use multi-factor authentication when signing in.
- **Suggested next step:** Enforce a Conditional Access policy requiring multi-factor authentication for all users.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies)
- **Technical id:** `id-ca-mfa-all-users`

### Keep Global Admin count between two and eight

- **Status:** Looking good
- **In plain English:** You have enough Global Admins for break-glass coverage without too many.
- **Suggested next step:** Reduce or increase Global Administrator principals to land between 2 and 8.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://portal.azure.com/#view/Microsoft_Azure_PIMCommon/CommonMenuBlade/~/quickStart)
- **Technical id:** `id-ga-count-bounds`

### Risk-based sign-in protection

- **Status:** Looking good
- **In plain English:** Suspicious sign-ins and risky accounts appear to trigger automatic extra checks or blocks.
- **Suggested next step:** Turn on risk-based sign-in protection in stages — start by requiring extra verification when Microsoft marks a sign-in as risky.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies)
- **Technical id:** `id-idprotect-off`

### Keep powerful admin accounts cloud-only

- **Status:** Looking good
- **In plain English:** Powerful admin accounts look separate from on-premises directories.
- **Suggested next step:** Use separate cloud-only accounts for highly privileged roles.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://portal.azure.com/#view/Microsoft_Azure_PIMCommon/CommonMenuBlade/~/quickStart)
- **Technical id:** `id-priv-cloud-only`

### Remove broad anti-spam allow lists

- **Status:** Looking good
- **In plain English:** No broad anti-spam allow lists are configured.
- **Suggested next step:** Clear AllowedSenders and AllowedSenderDomains from anti-spam policies.
- **Confidence:** High confidence
- **Data sources:** Exchange Online PowerShell (powershell.bridge), Security & Compliance PowerShell (scc_compliance)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://security.microsoft.com/antispam)
- **Technical id:** `mdo-anti-spam-no-allowed-domains`

### Clear the connection filter IP allow list

- **Status:** Looking good
- **In plain English:** No IP allow list bypasses email filtering.
- **Suggested next step:** Remove entries from the connection filter IP allow list.
- **Confidence:** High confidence
- **Data sources:** Exchange Online PowerShell (powershell.bridge), Security & Compliance PowerShell (scc_compliance)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://security.microsoft.com/antispam)
- **Technical id:** `mdo-connection-filter-no-ip-allow`

### Turn off the connection filter safe list

- **Status:** Looking good
- **In plain English:** Safe-list bypass is turned off.
- **Suggested next step:** Disable EnableSafeList on connection filter policies.
- **Confidence:** High confidence
- **Data sources:** Exchange Online PowerShell (powershell.bridge), Security & Compliance PowerShell (scc_compliance)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://security.microsoft.com/antispam)
- **Technical id:** `mdo-connection-filter-no-safe-list`

### Protect your own domains from look-alikes

- **Status:** Looking good
- **In plain English:** Look-alike domains are caught before they fool your users.
- **Suggested next step:** Enable organization domain impersonation protection.
- **Confidence:** High confidence
- **Data sources:** Exchange Online PowerShell (powershell.bridge), Security & Compliance PowerShell (scc_compliance)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://security.microsoft.com/antiphishing)
- **Technical id:** `mdo-impersonation-domains-owned`

### Block risky click-to-run attachments

- **Status:** Looking good
- **In plain English:** Risky file types like .exe are filtered from email.
- **Suggested next step:** Enable the common attachments filter including .exe, .cmd, and .vbe.
- **Confidence:** High confidence
- **Data sources:** Exchange Online PowerShell (powershell.bridge), Security & Compliance PowerShell (scc_compliance)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://security.microsoft.com/antimalwarev2)
- **Technical id:** `mdo-malware-file-filter`

### Turn on zero-hour auto purge for malware

- **Status:** Looking good
- **In plain English:** Delivered malware is automatically pulled back when detected.
- **Suggested next step:** Enable ZAP on anti-malware policies.
- **Confidence:** High confidence
- **Data sources:** Exchange Online PowerShell (powershell.bridge), Security & Compliance PowerShell (scc_compliance)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://security.microsoft.com/antimalwarev2)
- **Technical id:** `mdo-malware-zap`

### Turn on Safe Links and Safe Attachments for everyone

- **Status:** Looking good
- **In plain English:** Safe Links and Safe Attachments look enabled from a direct policy read.
- **Suggested next step:** Turn on Preset security policies (Standard) for all users in the Defender portal — Safe Links and Safe Attachments included.
- **Confidence:** High confidence
- **Data sources:** Exchange Online PowerShell (exo_threat_policies)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://security.microsoft.com/presetSecurityPolicies)
- **Technical id:** `mdo-p2-policies-default`

### Block malware found by Safe Attachments

- **Status:** Looking good
- **In plain English:** Suspicious attachments are blocked or removed before reaching users.
- **Suggested next step:** Set Safe Attachments unknown malware response to Block or Dynamic Delivery.
- **Confidence:** High confidence
- **Data sources:** Exchange Online PowerShell (powershell.bridge), Security & Compliance PowerShell (scc_compliance)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://security.microsoft.com/safeattachmentv2)
- **Technical id:** `mdo-safe-attachments-block`

### Scan files in SharePoint OneDrive and Teams

- **Status:** Looking good
- **In plain English:** Files in SharePoint, OneDrive, and Teams are scanned for malware.
- **Suggested next step:** Enable Defender for Office 365 for SharePoint, OneDrive, and Teams.
- **Confidence:** High confidence
- **Data sources:** Exchange Online PowerShell (powershell.bridge), Security & Compliance PowerShell (scc_compliance)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://security.microsoft.com/safeattachmentv2)
- **Technical id:** `mdo-safe-attachments-spo-teams`

### Screen links in email Teams and Office apps

- **Status:** Looking good
- **In plain English:** Links in email, Teams, and Office apps are screened.
- **Suggested next step:** Enable Safe Links for email, Teams, and Office apps.
- **Confidence:** High confidence
- **Data sources:** Exchange Online PowerShell (powershell.bridge), Security & Compliance PowerShell (scc_compliance)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://security.microsoft.com/safelinksv2)
- **Technical id:** `mdo-safe-links-block-list`

### Track clicks on rewritten links

- **Status:** Looking good
- **In plain English:** You can see who clicked risky links after the fact.
- **Suggested next step:** Enable Track user clicks in Safe Links policies.
- **Confidence:** High confidence
- **Data sources:** Exchange Online PowerShell (powershell.bridge), Security & Compliance PowerShell (scc_compliance)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://security.microsoft.com/safelinksv2)
- **Technical id:** `mdo-safe-links-click-tracking`

### Scan download links in real time

- **Status:** Looking good
- **In plain English:** Links pointing to files are scanned before delivery.
- **Suggested next step:** Enable real-time URL scanning and wait-for-scan before delivery.
- **Confidence:** High confidence
- **Data sources:** Exchange Online PowerShell (powershell.bridge), Security & Compliance PowerShell (scc_compliance)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://security.microsoft.com/safelinksv2)
- **Technical id:** `mdo-safe-links-real-time-scan`

### Show safety tips for unusual senders

- **Status:** Looking good
- **In plain English:** Users see warnings for unusual and look-alike senders.
- **Suggested next step:** Enable all anti-phish safety tips and indicators.
- **Confidence:** High confidence
- **Data sources:** Exchange Online PowerShell (powershell.bridge), Security & Compliance PowerShell (scc_compliance)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://security.microsoft.com/antiphishing)
- **Technical id:** `mdo-safety-tips-enabled`

### Keep spam and phishing out of inboxes

- **Status:** Looking good
- **In plain English:** Spam and phishing are kept out of user inboxes.
- **Suggested next step:** Set spam and phishing actions to quarantine or junk, not inbox delivery.
- **Confidence:** High confidence
- **Data sources:** Exchange Online PowerShell (powershell.bridge), Security & Compliance PowerShell (scc_compliance)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://security.microsoft.com/antispam)
- **Technical id:** `mdo-spam-phish-not-inbox`

### Turn on unified audit logging

- **Status:** Looking good
- **In plain English:** User and admin activity is being recorded for investigation.
- **Suggested next step:** Enable unified audit log ingestion.
- **Confidence:** High confidence
- **Data sources:** Exchange Online PowerShell (powershell.bridge), Security & Compliance PowerShell (scc_compliance)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://compliance.microsoft.com/auditlogsearch)
- **Technical id:** `mdo-unified-audit-enabled`

### Turn off Power BI publish to web

- **Status:** Looking good
- **In plain English:** Publish to web is off.
- **Suggested next step:** Disable publish to web in the Power BI admin portal.
- **Confidence:** High confidence
- **Data sources:** Power Platform / Power BI PowerShell (powershell.bridge)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://app.powerbi.com/admin-portal/tenantSettings)
- **Technical id:** `pbi-publish-to-web-disabled`

### Apply a DLP policy to every environment

- **Status:** Looking good
- **In plain English:** Every environment has a DLP policy.
- **Suggested next step:** Assign a DLP policy that covers every environment, including the default environment.
- **Confidence:** High confidence
- **Data sources:** Power Platform / Power BI PowerShell (powershell.bridge)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://admin.powerplatform.microsoft.com)
- **Technical id:** `pp-dlp-all-environments`

### Restrict environment creation to admins

- **Status:** Looking good
- **In plain English:** Environment creation is admin-only.
- **Suggested next step:** Turn off environment creation by non-admin users in the Power Platform admin center.
- **Confidence:** High confidence
- **Data sources:** Power Platform / Power BI PowerShell (powershell.bridge)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://admin.powerplatform.microsoft.com)
- **Technical id:** `pp-env-creation-admin-only`

### Restrict Power Pages creation to admins

- **Status:** Looking good
- **In plain English:** Power Pages creation is admin-only.
- **Suggested next step:** Turn off Power Pages creation by non-admin users in the Power Platform admin center.
- **Confidence:** High confidence
- **Data sources:** Power Platform / Power BI PowerShell (powershell.bridge)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://admin.powerplatform.microsoft.com)
- **Technical id:** `pp-pages-creation-admin-only`

### Turn on Power Platform tenant isolation

- **Status:** Looking good
- **In plain English:** Tenant isolation is enabled.
- **Suggested next step:** Enable tenant isolation in the Power Platform admin center and review allowlist exceptions.
- **Confidence:** High confidence
- **Data sources:** Power Platform / Power BI PowerShell (powershell.bridge)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://admin.powerplatform.microsoft.com)
- **Technical id:** `pp-tenant-isolation-enabled`

### Block sharing of sensitive information with DLP

- **Status:** Looking good
- **In plain English:** DLP blocks sensitive data from being shared with everyone.
- **Suggested next step:** Set DLP rule actions to block access for sensitive information.
- **Confidence:** High confidence
- **Data sources:** Exchange Online PowerShell (powershell.bridge), Security & Compliance PowerShell (scc_compliance)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://compliance.microsoft.com/datalossprevention)
- **Technical id:** `pur-dlp-enforcement-block`

### Notify users when they handle sensitive data

- **Status:** Looking good
- **In plain English:** Users get educated when they handle sensitive data.
- **Suggested next step:** Enable user notifications on DLP rules.
- **Confidence:** High confidence
- **Data sources:** Exchange Online PowerShell (powershell.bridge), Security & Compliance PowerShell (scc_compliance)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://compliance.microsoft.com/datalossprevention)
- **Technical id:** `pur-dlp-notifications`

### Create an enforced DLP policy for sensitive data

- **Status:** Looking good
- **In plain English:** At least one DLP policy is actively protecting sensitive data.
- **Suggested next step:** Create and enforce a DLP policy covering agency-defined sensitive information.
- **Confidence:** High confidence
- **Data sources:** scc_compliance
- **Limitations:** Sensitive-information-type coverage (SSN/ITIN/credit card) is not enumerated; verify rule content in the Purview portal
- **Admin page:** [Open Microsoft admin page](https://compliance.microsoft.com/datalossprevention)
- **Technical id:** `pur-dlp-policy-present`

### Apply retention policies to email and files

- **Status:** Looking good
- **In plain English:** Content retention rules are in place. Confirm durations match your legal or regulatory requirements.
- **Suggested next step:** Create retention policies with retention rules for Exchange, SharePoint, OneDrive, and Teams, then confirm the durations match your requirements.
- **Confidence:** High confidence
- **Data sources:** Microsoft Purview / Security & Compliance PowerShell (powershell.bridge)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://purview.microsoft.com/datalifecyclemanagement/retentionpolicies)
- **Technical id:** `pur-retention-policy-coverage`

### Publish sensitivity labels

- **Status:** Looking good
- **In plain English:** Sensitivity labels are available for people to apply to content.
- **Suggested next step:** Create a label policy that publishes your sensitivity labels to the people who handle sensitive content, then confirm the labels appear in Office apps.
- **Confidence:** High confidence
- **Data sources:** Microsoft Purview / Security & Compliance PowerShell (powershell.bridge)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://purview.microsoft.com/informationprotection/labelpolicies)
- **Technical id:** `pur-sensitivity-labels-published`

### Limit external sharing to approved partner domains

- **Status:** Looking good
- **In plain English:** External sharing is limited to approved partner domains.
- **Suggested next step:** Turn on domain allowlisting and add only your approved partner domains.
- **Confidence:** High confidence
- **Data sources:** Microsoft Teams / SharePoint Online PowerShell (powershell.bridge)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://admin.microsoft.com/sharepoint)
- **Technical id:** `spo-domain-restrictions`

### Restrict OneDrive sharing to existing guests

- **Status:** Looking good
- **In plain English:** OneDrive external sharing is restricted.
- **Suggested next step:** Set OneDrive sharing to existing guests or internal-only.
- **Confidence:** High confidence
- **Data sources:** Microsoft Teams / SharePoint Online PowerShell (powershell.bridge)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://admin.microsoft.com/sharepoint)
- **Technical id:** `spo-onedrive-sharing-limited`

### Restrict SharePoint sharing to existing guests

- **Status:** Looking good
- **In plain English:** SharePoint external sharing is restricted.
- **Suggested next step:** Set SharePoint sharing to existing guests or internal-only.
- **Confidence:** High confidence
- **Data sources:** Microsoft Teams / SharePoint Online PowerShell (powershell.bridge)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://admin.microsoft.com/sharepoint)
- **Technical id:** `spo-sharing-capability-limited`

### Block anonymous users from starting meetings

- **Status:** Looking good
- **In plain English:** Anonymous attendees cannot start meetings on their own.
- **Suggested next step:** Turn off 'Anonymous users and dial-in callers can start a meeting'.
- **Confidence:** High confidence
- **Data sources:** Microsoft Teams / SharePoint Online PowerShell (powershell.bridge)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://admin.teams.microsoft.com)
- **Technical id:** `teams-anonymous-start-disabled`

### Allow external access only for specific domains

- **Status:** Looking good
- **In plain English:** External access is limited to specific partner domains.
- **Suggested next step:** Allow only specific external domains, not all.
- **Confidence:** High confidence
- **Data sources:** Microsoft Teams / SharePoint Online PowerShell (powershell.bridge)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://admin.teams.microsoft.com)
- **Technical id:** `teams-external-access-per-domain`

### Block unmanaged users from contacting you first

- **Status:** Looking good
- **In plain English:** Unmanaged accounts cannot reach your team first.
- **Suggested next step:** Block inbound contact from unmanaged Teams accounts.
- **Confidence:** High confidence
- **Data sources:** Microsoft Teams / SharePoint Online PowerShell (powershell.bridge)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://admin.teams.microsoft.com)
- **Technical id:** `teams-unmanaged-inbound-blocked`

### Nothing may happen when a device falls out of compliance

- **Status:** Looking good
- **In plain English:** Falling out of compliance triggers an action.
- **Suggested next step:** Configure a noncompliance action (such as notify or block access) on each compliance policy.
- **Confidence:** High confidence
- **Data sources:** graph.deviceManagement
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://endpoint.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesComplianceMenu/~/policies)
- **Technical id:** `endpoint-compliance-noncompliance-action`

### No security baseline may be applied to devices

- **Status:** Looking good
- **In plain English:** A security baseline is applied to managed devices.
- **Suggested next step:** Deploy a Microsoft security baseline profile to your managed devices and monitor its adoption.
- **Confidence:** High confidence
- **Data sources:** graph.deviceManagement
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://endpoint.microsoft.com/#view/Microsoft_Intune_Workflows/SecurityManagementMenu/~/overview)
- **Technical id:** `endpoint-security-baseline`

### Shorten long-lived app certificates

- **Status:** Looking good
- **In plain English:** App certificates we could see stay within a reasonable lifetime.
- **Suggested next step:** Keep application certificate lifetimes at 365 days or less and rotate on schedule.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade)
- **Technical id:** `id-app-certificate-lifetime`

### Shorten long-lived app secrets

- **Status:** Looking good
- **In plain English:** App secrets we could see stay within a reasonable lifetime.
- **Suggested next step:** Rotate app secrets and keep password credential lifetime at 180 days or less.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade)
- **Technical id:** `id-app-password-lifetime`

### Turn off external Power BI invitations

- **Status:** Looking good
- **In plain English:** External invitations are off.
- **Suggested next step:** Disable external invitations in the Power BI admin portal.
- **Confidence:** High confidence
- **Data sources:** Power Platform / Power BI PowerShell (powershell.bridge)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://app.powerbi.com/admin-portal/tenantSettings)
- **Technical id:** `pbi-external-invite-disabled`

### Turn off Power BI guest access

- **Status:** Looking good
- **In plain English:** Guest access is off.
- **Suggested next step:** Disable guest user access in the Power BI admin portal.
- **Confidence:** High confidence
- **Data sources:** Power Platform / Power BI PowerShell (powershell.bridge)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://app.powerbi.com/admin-portal/tenantSettings)
- **Technical id:** `pbi-guest-access-disabled`

### Turn off Python and R visuals

- **Status:** Looking good
- **In plain English:** Python and R visuals are off.
- **Suggested next step:** Disable Python and R visuals in the Power BI admin portal.
- **Confidence:** High confidence
- **Data sources:** Power Platform / Power BI PowerShell (powershell.bridge)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://app.powerbi.com/admin-portal/tenantSettings)
- **Technical id:** `pbi-python-r-visuals-disabled`

### Block Power BI resource key authentication

- **Status:** Looking good
- **In plain English:** Resource key authentication is blocked.
- **Suggested next step:** Block resource key authentication in the Power BI admin portal.
- **Confidence:** High confidence
- **Data sources:** Power Platform / Power BI PowerShell (powershell.bridge)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://app.powerbi.com/admin-portal/tenantSettings)
- **Technical id:** `pbi-resource-key-auth-blocked`

### Turn on Power BI sensitivity labels

- **Status:** Looking good
- **In plain English:** Sensitivity labels are applied to Power BI content.
- **Suggested next step:** Enable sensitivity labels in the Power BI admin portal and publish label policies.
- **Confidence:** High confidence
- **Data sources:** Power Platform / Power BI PowerShell (powershell.bridge)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://app.powerbi.com/admin-portal/tenantSettings)
- **Technical id:** `pbi-sensitivity-labels-enabled`

### Restrict Power BI API access for service principals

- **Status:** Looking good
- **In plain English:** Service principal API access is restricted to allowed groups.
- **Suggested next step:** Restrict service principal API access to specific security groups or disable it.
- **Confidence:** High confidence
- **Data sources:** Power Platform / Power BI PowerShell (powershell.bridge)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://app.powerbi.com/admin-portal/tenantSettings)
- **Technical id:** `pbi-sp-api-restricted`

### Turn off service principal profiles

- **Status:** Looking good
- **In plain English:** Service principal profiles are off.
- **Suggested next step:** Disable service principal profile creation in the Power BI admin portal.
- **Confidence:** High confidence
- **Data sources:** Power Platform / Power BI PowerShell (powershell.bridge)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://app.powerbi.com/admin-portal/tenantSettings)
- **Technical id:** `pbi-sp-profiles-disabled`

### Block sharing apps with everyone

- **Status:** Looking good
- **In plain English:** Share-with-everyone is disabled.
- **Suggested next step:** Disable share-with-everyone in the Power Platform admin center.
- **Confidence:** High confidence
- **Data sources:** Power Platform / Power BI PowerShell (powershell.bridge)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://admin.powerplatform.microsoft.com)
- **Technical id:** `pp-share-with-everyone-disabled`

### Restrict trial environment creation to admins

- **Status:** Looking good
- **In plain English:** Trial environment creation is admin-only.
- **Suggested next step:** Turn off trial environment creation by non-admin users in the Power Platform admin center.
- **Confidence:** High confidence
- **Data sources:** Power Platform / Power BI PowerShell (powershell.bridge)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://admin.powerplatform.microsoft.com)
- **Technical id:** `pp-trial-creation-admin-only`

### Default new links to specific people

- **Status:** Looking good
- **In plain English:** New sharing links only reach the specific people you choose.
- **Suggested next step:** Set the default sharing link type to specific people.
- **Confidence:** High confidence
- **Data sources:** Microsoft Teams / SharePoint Online PowerShell (powershell.bridge)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://admin.microsoft.com/sharepoint)
- **Technical id:** `spo-default-link-specific`

### Default new links to view-only

- **Status:** Looking good
- **In plain English:** New sharing links are view-only by default.
- **Suggested next step:** Set the default sharing link permission to view.
- **Confidence:** High confidence
- **Data sources:** Microsoft Teams / SharePoint Online PowerShell (powershell.bridge)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://admin.microsoft.com/sharepoint)
- **Technical id:** `spo-default-link-view`

### Require verification-code reauthentication within 30 days

- **Status:** Looking good
- **In plain English:** Verification-code access reauthenticates within a safe window.
- **Suggested next step:** Require verification-code users to reauthenticate within 30 days.
- **Confidence:** High confidence
- **Data sources:** Microsoft Teams / SharePoint Online PowerShell (powershell.bridge)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://admin.microsoft.com/sharepoint)
- **Technical id:** `spo-verification-reauth`

### Hold anonymous and dial-in callers in the lobby

- **Status:** Looking good
- **In plain English:** Unmanaged attendees wait in the lobby.
- **Suggested next step:** Keep 'Who can bypass the lobby' away from Everyone.
- **Confidence:** High confidence
- **Data sources:** Microsoft Teams / SharePoint Online PowerShell (powershell.bridge)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://admin.teams.microsoft.com)
- **Technical id:** `teams-anonymous-lobby`

### Keep dial-in callers in the lobby

- **Status:** Looking good
- **In plain English:** Dial-in callers wait in the lobby.
- **Suggested next step:** Turn off 'People dialing in can bypass the lobby'.
- **Confidence:** High confidence
- **Data sources:** Microsoft Teams / SharePoint Online PowerShell (powershell.bridge)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://admin.teams.microsoft.com)
- **Technical id:** `teams-dialin-lobby`

### Disable channel email integration

- **Status:** Looking good
- **In plain English:** Channels cannot receive external email.
- **Suggested next step:** Turn off 'Users can send emails to a channel email address'.
- **Confidence:** High confidence
- **Data sources:** Microsoft Teams / SharePoint Online PowerShell (powershell.bridge)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://admin.teams.microsoft.com)
- **Technical id:** `teams-email-integration-disabled`

### Block external participants from taking control

- **Status:** Looking good
- **In plain English:** External attendees cannot take over shared screens.
- **Suggested next step:** Turn off 'External participants can give or request control'.
- **Confidence:** High confidence
- **Data sources:** Microsoft Teams / SharePoint Online PowerShell (powershell.bridge)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://admin.teams.microsoft.com)
- **Technical id:** `teams-external-control-disabled`

### Block internal users from contacting unmanaged accounts

- **Status:** Looking good
- **In plain English:** Your team cannot reach unmanaged accounts.
- **Suggested next step:** Block outbound contact to unmanaged Teams accounts.
- **Confidence:** High confidence
- **Data sources:** Microsoft Teams / SharePoint Online PowerShell (powershell.bridge)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://admin.teams.microsoft.com)
- **Technical id:** `teams-unmanaged-outbound-blocked`

### Cross-product incident correlation may not be active

- **Status:** Looking good
- **In plain English:** Cross-product incidents are being correlated, so XDR is actively in use.
- **Suggested next step:** Confirm XDR is enabled and that identity, email, and endpoint signals are connected in the Microsoft Defender portal.
- **Confidence:** High confidence
- **Data sources:** graph.security.incidents
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://security.microsoft.com/incidents)
- **Technical id:** `xdr-incident-readiness`

### Auto-admit internal users to meetings

- **Status:** Looking good
- **In plain English:** Your team joins meetings without lobby friction.
- **Suggested next step:** Set 'Who can bypass the lobby' to People in my org.
- **Confidence:** High confidence
- **Data sources:** Microsoft Teams / SharePoint Online PowerShell (powershell.bridge)
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://admin.teams.microsoft.com)
- **Technical id:** `teams-internal-auto-admit`

### Turn on Defender for Cloud protection for your subscription

- **Status:** Not in your plan
- **In plain English:** This protection does not appear to be included in the licenses we detected, so there is nothing to configure for it yet.
- **Suggested next step:** If you expected this capability, confirm the correct Microsoft plan is assigned, or talk to your licensing partner.
- **Confidence:** High confidence
- **Data sources:** graph.subscribedSkus
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://learn.microsoft.com/azure/defender-for-cloud/enable-enhanced-security)
- **Technical id:** `az-defender-plan-enabled`

### Confirm Premium capacity governance and entitlement use

- **Status:** Not in your plan
- **In plain English:** This protection does not appear to be included in the licenses we detected, so there is nothing to configure for it yet.
- **Suggested next step:** If you expected this capability, confirm the correct Microsoft plan is assigned, or talk to your licensing partner.
- **Confidence:** High confidence
- **Data sources:** graph.subscribedSkus
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://app.powerbi.com/admin-portal/capacities)
- **Technical id:** `pbi-premium-capacity-governance`

### Review Azure resource posture in Defender for Cloud

- **Status:** Not in your plan
- **In plain English:** This protection does not appear to be included in the licenses we detected, so there is nothing to configure for it yet.
- **Suggested next step:** If you expected this capability, confirm the correct Microsoft plan is assigned, or talk to your licensing partner.
- **Confidence:** High confidence
- **Data sources:** graph.subscribedSkus
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://learn.microsoft.com/azure/defender-for-cloud/secure-score-security-controls)
- **Technical id:** `az-cspm-out-of-scope`

## Technical details

- Owned capability ids: conditional_access, defender_endpoint_p2, defender_identity, defender_office_p1, defender_office_p2, defender_xdr, entra_id_p2, exchange_online, exchange_online_protection, identity_protection, intune, log_analytics, microsoft_sentinel, onedrive_for_business, power_bi_pro, power_platform, purview_audit, purview_communication_compliance, purview_dlp, purview_ediscovery, purview_insider_risk, purview_retention, purview_sensitivity_labels, sharepoint_online, teams

- SKU `SPE_E5` (87/100): AAD_PREMIUM_P2, MFA_PREMIUM, ADALLOM_S_O365, EQUIVIO_ANALYTICS, LOCKBOX_ENTERPRISE, MIP_S_CLP2, THREAT_INTELLIGENCE, DEFENDER_ENDPOINT_P2
- SKU `MICROSOFT_SENTINEL` (1/1): MICROSOFT_SENTINEL
