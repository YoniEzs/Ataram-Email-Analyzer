# Cloudflare Zero Trust setup — analyzer.itgalya.com

Dashboard steps to protect the deployed app with an Access application using
email one-time-PIN login. Verified against Cloudflare docs current as of
2026-08-08.

> **Navigation changed in Nov 2025.** The second nav segment is now
> **Access controls**, not "Access". Identity providers moved out of
> Settings entirely. Any older guide saying *Access > Applications* or
> *Settings > Authentication > Login methods* is stale.
>
> The top-level sidebar item may read either **Zero Trust** or **Cloudflare One**
> — docs still say Zero Trust, the dashboard host is `one.dash.cloudflare.com`.
> Use **Access controls** as the reliable landmark.

## Order matters

DNS goes **last**. Creating the CNAME before the Access application exists makes
`analyzer.itgalya.com` reachable by anyone on the internet, unauthenticated, for
as long as the gap lasts. Cloudflare states this explicitly:

> We recommend creating an Access application before setting up the tunnel route.
> If you do not have an Access application in place, the published application
> will be available to anyone on the Internet.

Right now there is no DNS record for the hostname, which is the safe state. Keep
it that way until step 5.

---

## 1. Add One-time PIN as an identity provider

**Zero Trust → Integrations → Identity providers → Add new identity provider →
One-time PIN → Save**

OTP has no configuration fields; adding it is the whole setup.

Do not assume it is already there. Since 2026-06-18 new accounts get the
Cloudflare identity provider by default and **OTP is no longer added
automatically**. Accounts created before that keep whatever they had — so check
rather than assume.

## 2. Create the policy

**Zero Trust → Access controls → Policies → Add a policy**

| Field | Value |
|---|---|
| Policy name | `Analyzer users` |
| Action | `Allow` |
| Session duration | leave as `Same as application session timeout` |

Rules:

- **Include** → `Emails ending in` → `@itgalya.com`
  (or **Include** → `Emails` → the exact addresses)
- **Require** → `Login methods` → `One-time PIN`

> **Do not put One-time PIN in an Include rule.** Cloudflare's own warning:
> adding it as Include without restricting email domains "allows anyone with any
> email address to receive a code and access the application." Include decides
> *who*; Require decides *how*.

Access is deny-by-default — a user must match an Allow policy to get in.

## 3. Create the application

**Zero Trust → Access controls → Applications → Create new application →
Self-hosted and private → Add public hostname**

There is no standalone "Self-hosted" tile any more; public vs private is decided
by choosing *Add public hostname* on the following screen.

- **Domain**: pick `itgalya.com` from the dropdown (it lists active zones — no
  DNS record needs to exist yet)
- **Subdomain**: `analyzer`
- **Path**: **leave empty** — this is what makes one application cover both the
  static frontend and the Flask `/api/...` routes
- **Access policies**: attach `Analyzer users` from step 2
- **Identity providers**: enable **only** One-time PIN
- **Apply instant authentication**: on (with a single IdP this skips the chooser
  page and goes straight to the email prompt)
- **Authenticate with Cloudflare One Client**: off
- **Session Duration**: 24 hours is the default and is fine

Leave the CORS section alone — frontend and API are the same origin, and CORS
checks do not occur on the same domain.

To make it appear as a tile in the App Launcher
(`https://<your-team-name>.cloudflareaccess.com`), turn on **Show application in
App Launcher** under the **Experience settings** tab. Cosmetic only: allowed
users can always reach the app by direct link either way.

## 4. Record the AUD tag

On the application's **Overview** tab, copy the **Audience (AUD) tag**. Step 6
needs it.

## 5. Create DNS — the exposure step

In the **itgalya.com** zone, **DNS → Records → Add record**:

| Field | Value |
|---|---|
| Type | `CNAME` |
| Name | `analyzer` |
| Target | `60200874-f30b-4062-b8c0-67811340916b.cfargotunnel.com` |
| Proxy status | **Proxied** (orange cloud) |

Proxied is mandatory, for two independent reasons: `cfargotunnel.com` only
resolves inside Cloudflare's edge, and Access can only run in the edge request
path. A grey-cloud record breaks both.

Create it by hand rather than with `cloudflared tunnel route dns` — that command
needs a `cert.pem` scoped to the `itgalya.com` zone. The one on this machine is
scoped to `ataram.uk`, which is what produced the bogus record in the cleanup
note below.

## 6. Close the origin-bypass hole — DONE

Access is enforced only at Cloudflare's edge, so it does not protect the origin
by itself. `cloudflared/config.yml` now carries:

```yaml
      access:
        required: true
        teamName: ataraxcode
        audTag:
          - 270a318a1434863bf02f27a881039a30493b9df8bea035ba7752c535443b3031
```

cloudflared verifies the Access JWT before proxying to nginx, so a request that
reaches the tunnel without a valid token for *this* application is rejected at
the connector.

Both values were read off the Access login redirect: the team domain is
`ataraxcode.cloudflareaccess.com`, and the AUD tag is the `aud` claim of the
meta token Access mints (it also appears as the `kid` query parameter).

If a valid login ever starts failing at the connector, this block is the first
suspect — revert with:

```bash
ssh itgalya-app01 "cd ~/ataram-analyzer && sed -i 's/^        required: true/        required: false/' cloudflared/config.yml && docker compose up -d --force-recreate cloudflared"
```

## 7. Verify

In a private window, open `https://analyzer.itgalya.com`. Expected: the Access
email prompt → enter an allowed address → **Send login code** → an email from
`noreply@notify.cloudflare.com` → paste the PIN → the app loads.

The PIN expires 10 minutes after the request, is single-use, and requesting a new
one invalidates the previous one.

Then test an address the policy does **not** allow. It must receive nothing at
all — Cloudflare sends no email and shows no error. This silent no-op is the most
common cause of "the OTP email never arrived", so check the policy first when
debugging. Note also that Access only logs an authentication attempt once a code
is submitted, so a request that never gets completed leaves no audit trail.

In Firefox private windows, tracking prevention can block the `CF_Authorization`
cookie on XHR — exempt both `analyzer.itgalya.com` and your team domain when
testing.

## 8. Audit for sibling exposure

Confirm no *other* proxied DNS record in the account points at tunnel
`60200874-f30b-4062-b8c0-67811340916b` on a hostname that no Access application
covers. Such a record reaches the same nginx with no authentication. Step 6
closes this at the connector, which is why it is not optional.

---

## Is this two-factor authentication?

**No — One-time PIN is a single factor.** It is a login method configured as an
identity provider, an alternative to an IdP rather than a step on top of one. An
app protected only by OTP is guarded by exactly one thing: control of an inbox
whose address the policy permits.

Cloudflare never states this in so many words, but it follows from how the
product is laid out: OTP is documented as an identity provider, the login page
offers "your identity provider **or** a one-time PIN", and Cloudflare's Enforce
MFA page lists only authenticator apps, security keys, biometrics and PIV keys as
MFA methods — emailed OTP is absent.

For genuine 2FA, layer **Independent MFA** on top (Zero Trust → Access controls →
Access settings, or per-application/per-policy). It prompts for a second factor
inside Access itself, is IdP-agnostic, and therefore works on top of an OTP
login. Supported second factors: authenticator apps (TOTP), hardware security
keys, biometrics, PIV keys.

Two caveats: the App Launcher is deliberately exempt from the global MFA
requirement so users can enroll authenticators, so an OTP inbox alone still gates
first-time enrollment; and OTP passes no AMR value, so OTP users always get the
Access-side prompt.

## Cleanup

Delete the stray CNAME **`analyzer.itgalya.com.ataram.uk`** in the **ataram.uk**
zone. `cloudflared tunnel route dns` created it against a cert scoped to
`ataram.uk`, so it appended the wrong suffix and attached it to the wrong tunnel.

## Things to confirm against the live UI

Cloudflare's docs are internally inconsistent on a few labels. Where they
disagree, trust the screen:

- **Additional settings** vs **Advanced settings** — both appear in current docs
  for the same tab.
- Whether **Subdomain** and **Path** render as separate fields beside the Domain
  dropdown. Two pages updated the same day contradict each other.
- Session Duration option strings are never published; only
  `Same as application session timeout` and `No duration, expires immediately`
  are confirmed verbatim.
- Selector capitalization drifts between `Emails` / `Email` and
  `Login methods` / `Login Methods`.
