# Security License Lens report

A plain-language view of security capabilities you already pay for — and whether they are set up to help your organization.

- **Version:** 0.3.0
- **Scanned at:** 2026-08-13T00:00:00+00:00
- **Mode:** dry_run / dry_run
- **Organization:** Contoso Demo (dry-run)

## At a glance

**3 of 4 still not fully working.**

- **Licensed capabilities detected:** 8
- **Prioritized capabilities:** 4 (priority packs: identity, endpoint)
- **Fully working:** 1 of 4 prioritized capabilities (25% realized)
- **Need attention:** 3 of 4 prioritized capabilities

### Top things to do first

1. **Require multi-factor authentication for admins and block legacy email sign-in methods that skip modern security prompts** *(~a few hours)* — Some sign-in protections are present, but the full set is not enforced yet (multi-factor authentication and/or blocking outdated sign-in methods).
   - Next step: Require multi-factor authentication for admins and block legacy email sign-in methods that skip modern security prompts.
2. **Create equivalent Conditional Access policies for MFA and legacy-authentication blocking in report-only mode** *(~a few hours)* — Security Defaults already includes baseline MFA protection and blocks outdated sign-in methods. Your plan also includes smarter sign-in rules you can customize, but that paid capability remains unused.
   - Next step: Create equivalent Conditional Access policies for MFA and legacy-authentication blocking in report-only mode. Validate coverage, exclusions, emergency access, and sign-in impact; then perform a controlled cutover from Security Defaults to the validated policies.
3. **Create an Access Review for your Global Administrators and guest users (monthly or quarterly), then review the first round of results** *(~a few hours)* — Your plan can periodically confirm who still needs powerful access and clean up old guest accounts. That process does not look set up yet.
   - Next step: Create an Access Review for your Global Administrators and guest users (monthly or quarterly), then review the first round of results.

*Effort is a rough guide, not a quote.*

- **Needs attention** (`gap`): 7
- **Looking good** (`ok`): 1
- **Partly set up** (`partial`): 3
- **Check pending** (`skipped`): 1

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

### Stronger email and file threat protection

*Microsoft name: Microsoft Defender for Office 365 P2*

- **What it does:** Open risky attachments and links in a safe way, catch advanced phishing, and investigate email threats faster when something slips through.
- **Why it matters:** Most business breaches still start with email. Better email protection reduces ransomware and invoice fraud.
- **If unused:** Extra email protections in your license may still be off, in test mode, or only covering a few people.
- **Included through license SKU(s):** SPE_E5
- **Matching service plan(s):** THREAT_INTELLIGENCE

### Stronger control over admin accounts

*Microsoft name: Microsoft Entra ID P2*

- **What it does:** Give people powerful admin rights only when they need them, and get better tools to catch risky sign-ins on high-value accounts.
- **Why it matters:** Admin accounts are the keys to your email, files, and business apps. If one is stolen, an attacker can look like a trusted employee.
- **If unused:** You are paying for stronger admin protections that are not fully turned on yet.
- **Included through license SKU(s):** SPE_E5
- **Matching service plan(s):** AAD_PREMIUM_P2

### Alerts when a sign-in looks suspicious

*Microsoft name: Microsoft Entra ID Protection*

- **What it does:** Automatically spot odd sign-in behavior (impossible travel, leaked passwords, unfamiliar locations) and require extra proof or block access.
- **Why it matters:** Attackers often use valid passwords. Risk detection helps catch the session even when the password was correct.
- **If unused:** Suspicious-sign-in protection is included in your plan but may not be enforcing anything yet.
- **Included through license SKU(s):** SPE_E5
- **Matching service plan(s):** AAD_PREMIUM_P2

### A central security command center in the cloud

*Microsoft name: Microsoft Sentinel*

- **What it does:** Bring security signals together in one place, detect patterns humans miss, and automate parts of incident response.
- **Why it matters:** Without a place that correlates events, teams drown in alerts from many products and miss the story that ties them together.
- **If unused:** A security workspace may exist, but few detections or smart analytics are turned on.
- **Included through license SKU(s):** MICROSOFT_SENTINEL
- **Matching service plan(s):** MICROSOFT_SENTINEL

### Guardrails so sensitive data is harder to leak

*Microsoft name: Microsoft Purview Data Loss Prevention*

- **What it does:** Warn or block people when they try to share credit cards, health data, or other sensitive information in the wrong place.
- **Why it matters:** Accidental oversharing is common. Guardrails protect customers and reduce regulatory and reputational harm.
- **If unused:** Data-protection rules may be missing or still in "test only" mode, so nothing is enforced yet.
- **Included through license SKU(s):** SPE_E5
- **Matching service plan(s):** MIP_S_CLP2


## Where you may not be getting the full benefit

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

### Set up periodic access reviews for admins and guests

- **Status:** Needs attention
- **In plain English:** Your plan can periodically confirm who still needs powerful access and clean up old guest accounts. That process does not look set up yet.
- **Suggested next step:** Create an Access Review for your Global Administrators and guest users (monthly or quarterly), then review the first round of results.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_ERM/DashboardBlade)
- **Technical id:** `id-access-reviews-unused`

### Powerful accounts that nobody uses are still switched on

- **Status:** Needs attention
- **In plain English:** Some powerful accounts are still switched on but have not been used recently. Unused admin accounts are a favorite target for attackers.
- **Suggested next step:** Review enabled admin accounts that have not signed in for a long time; disable or remove access you no longer need.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_IAM/SignInEventsBlade)
- **Technical id:** `id-dormant-privileged`

### Guardrails against accidental data leaks may not be active

- **Status:** Needs attention
- **In plain English:** You appear to pay for data-leak protection that is not meaningfully enforced yet. Confirm in the Purview portal.
- **Suggested next step:** Start with a simple policy for email and cloud files that detects obvious sensitive data, then move from "test" to "enforce" after a short tuning period.
- **Confidence:** Low confidence — verify in portal
- **Data sources:** secureScore.controlScores (proxy)
- **Limitations:** Secure Score proxy — verify DLP enforce mode in Purview portal; Based on Microsoft Secure Score signals — confirm the real setting in the Microsoft 365 / security admin portal before treating this as definitive
- **Admin page:** [Open Microsoft admin page](https://purview.microsoft.com/policiespage)
- **Technical id:** `pur-dlp-not-enforced`

### Behavior-based detection may still be switched off

- **Status:** Needs attention
- **In plain English:** Behavior analytics that learn normal patterns for people and devices still looks switched off.
- **Suggested next step:** Ask your security admin to turn on behavior analytics (UEBA) in the security workspace and connect the main data sources it needs.
- **Confidence:** Medium confidence
- **Data sources:** azure.arm.securityInsights
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://learn.microsoft.com/azure/sentinel/enable-entity-behavior-analytics)
- **Technical id:** `sen-ueba-not-enabled`

### Powerful accounts may sign in without strong extra checks

- **Status:** Partly set up
- **In plain English:** Some sign-in protections are present, but the full set is not enforced yet (multi-factor authentication and/or blocking outdated sign-in methods).
- **Suggested next step:** Require multi-factor authentication for admins and block legacy email sign-in methods that skip modern security prompts.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies)
- **Technical id:** `id-ca-priv-gaps`

### Your security command center may have few alarms turned on

- **Status:** Partly set up
- **In plain English:** Some detection alarms are on, but coverage still looks light for a paid security command center.
- **Suggested next step:** Enable a starter set of detection rules for sign-ins, email, and devices, then expand coverage with your IT or security partner.
- **Confidence:** Medium confidence
- **Data sources:** azure.arm.securityInsights
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://learn.microsoft.com/azure/sentinel/detect-threats-built-in)
- **Technical id:** `sen-analytics-rule-coverage`

### On-site directory servers may lack attack sensors

- **Status:** Partly set up
- **In plain English:** We could not confirm whether on-site directory attack sensors are installed. If you still run office domain controllers, ask IT to verify.
- **Suggested next step:** Confirm whether you still use on-site directory servers; if yes, install and health-check the identity sensors on each one.
- **Confidence:** Low confidence — verify in portal
- **Data sources:** secureScore.controlScores (proxy)
- **Limitations:** Secure Score proxy — verify MDI sensors in the Defender portal; Based on Microsoft Secure Score signals — confirm the real setting in the Microsoft 365 / security admin portal before treating this as definitive
- **Admin page:** [Open Microsoft admin page](https://security.microsoft.com/health)
- **Technical id:** `mdi-sensors-missing`

### Turn on Safe Links and Safe Attachments for everyone

- **Status:** Check pending
- **In plain English:** We cannot automatically confirm whether extra email protections (Safe Links and Safe Attachments) cover everyone. Ask IT to check Preset security policies in the Microsoft Defender portal, or run Exchange Online PowerShell (Get-ATPProtectionPolicyRule).
- **Suggested next step:** Open Preset security policies in the Defender portal and turn on Standard protection for all users, or confirm with Exchange Online PowerShell.
- **Confidence:** Low confidence — verify in portal
- **Data sources:** Not reported
- **Limitations:** Email policy config is PowerShell-only; not verified automatically
- **Admin page:** [Open Microsoft admin page](https://security.microsoft.com/presetSecurityPolicies)
- **Technical id:** `mdo-p2-policies-default`

### Risk-based sign-in protection

- **Status:** Looking good
- **In plain English:** Suspicious sign-ins and risky accounts appear to trigger automatic extra checks or blocks.
- **Suggested next step:** Turn on risk-based sign-in protection in stages — start by requiring extra verification when Microsoft marks a sign-in as risky.
- **Confidence:** High confidence
- **Data sources:** microsoft.graph
- **Limitations:** None reported
- **Admin page:** [Open Microsoft admin page](https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies)
- **Technical id:** `id-idprotect-off`

## Technical details

- Owned capability ids: conditional_access, defender_endpoint_p2, defender_identity, defender_office_p2, entra_id_p2, identity_protection, microsoft_sentinel, purview_dlp

- SKU `SPE_E5` (87/100): AAD_PREMIUM_P2, MFA_PREMIUM, ADALLOM_S_O365, EQUIVIO_ANALYTICS, LOCKBOX_ENTERPRISE, MIP_S_CLP2, THREAT_INTELLIGENCE, DEFENDER_ENDPOINT_P2
- SKU `MICROSOFT_SENTINEL` (1/1): MICROSOFT_SENTINEL
