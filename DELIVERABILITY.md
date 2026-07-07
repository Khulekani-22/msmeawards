# Contact‑form email deliverability (Resend → Microsoft 365)

## TL;DR

The contact form sends via **Resend** (Amazon SES infrastructure, eu‑west‑1) and
delivers to **`info@msmeawards.org`**, which is a **Microsoft 365 / Exchange
Online** mailbox.

Authentication is fully set up and **passes**:

| Check | Status | Notes |
| --- | --- | --- |
| Resend domain | **Verified** | `msmeawards.org` verified in Resend |
| SPF | **Pass** | root TXT includes `include:amazonses.com` |
| DKIM | **Pass / aligned** | `resend._domainkey.msmeawards.org` present |
| DMARC | **Pass** | `_dmarc` = `v=DMARC1; p=none;` |

Because authentication passes, **Resend returns HTTP `200`** and the mail is
**not** bounced. A `200` from Resend only means *"accepted into the send
queue,"* **not** *"delivered to the inbox."*

## Why messages don't land despite a 200

**Confirmed (Exchange admin → Mail flow → Accepted domains):**
`msmeawards.org` is an **Authoritative accepted domain** in the Microsoft 365
tenant (the shared `22onsloane.co` tenant), with *"Allow mail to be sent from
this domain"* enabled and *"Accept mail for all subdomains"* **disabled**.

**Confirmed (live MX):** `msmeawards.org` → `msmeawards-org.mail.protection.outlook.com`
— inbound mail goes **directly to Microsoft 365**. There is **no Mimecast in the
inbound path**, so a Mimecast allow‑list does **not** affect this mail (see note
below).

When a message arrives **from an external server** (Resend/SES) with a `From:`
on `msmeawards.org` — an **authoritative** domain — addressed to a mailbox on
that **same** domain, Microsoft Defender / EOP **spoof intelligence** treats it
as *intra‑org spoofing* (the "attacker sends as my own domain to my staff"
pattern) and **Quarantines or Junks it silently** — even though SPF + DKIM +
DMARC pass and both mailboxes are real. `DMARC p=none` means M365 trusts its own
heuristics over DMARC.

### 🔑 Critical consequence: `noreply@` alone does **not** fix this

Because the **whole domain** is authoritative, the spoof engine keys on the
**domain**, not the mailbox. `noreply@msmeawards.org → info@msmeawards.org` is
*still* intra‑org spoofing — changing `info@` to `noreply@` only avoids the
literal same‑mailbox case; it does **not** clear the spoof classification. To
actually fix inbox delivery you must do **one** of:

- **Path A — send from a *subdomain*** that is **not** an accepted domain (e.g.
  `noreply@send.msmeawards.org`). Because *"Accept mail for all subdomains"* is
  **off**, a subdomain is treated as a normal external sender, **not** spoofing.
  ✅ *Recommended — no tenant‑policy change, spoof‑proof, survives policy resets.*
- **Path B — explicitly allow the spoof in Microsoft 365** (Tenant Allow/Block
  List, or a DKIM‑scoped transport rule). Must be done in **M365**, not Mimecast.

> **About the Mimecast allow‑list you added:** the live MX for `msmeawards.org`
> points at `*.mail.protection.outlook.com`, i.e. **Microsoft 365 receives this
> mail directly**. Unless a Mimecast inbound connector is in front of EOP for
> this specific domain, that allow‑list has **no effect** on the contact‑form
> mail. The filter to change is **Microsoft Defender / EOP**, not Mimecast.

This is a **tenant‑policy / sender‑domain** issue, not a code or Resend issue.

## ⚠️ If the Resend log still shows `from: info@msmeawards.org`

The Resend **request body** is the source of truth for what was actually sent.
If it shows:

```
"from": "Presidential MSME Awards <info@msmeawards.org>",
"to":   ["info@msmeawards.org"]
```

…then `from == to` (same mailbox) — the **worst case** for intra‑org spoof
filtering — and the `RESEND_FROM_EMAIL=noreply@…` fix is **not active in the
environment that sent it**.

> **Gotcha:** editing the local `.env` does **nothing** for production. Vercel
> serverless functions read the env vars configured in **Vercel → Project →
> Settings → Environment Variables**. After changing them you must **redeploy**
> (or trigger a new deployment) for functions to pick them up.

**Fix:** set `RESEND_FROM_EMAIL=noreply@msmeawards.org` in Vercel (all
environments), redeploy, submit a fresh test, and re‑check the Resend request
body — `from` should now read `noreply@msmeawards.org` and differ from `to`.

## Reply‑To mismatch (Mimecast / M365 impersonation protection)

The form sets `Reply-To` to the visitor (e.g.
`Khulekani Mncube <khulekani@22onsloane.co>`) so staff can reply directly. This
value is header‑injection‑safe, but a **From domain ≠ Reply‑To domain** mismatch
is a recognised **impersonation / "reply‑to mismatch"** signal:

- Mimecast **Impersonation Protect** and M365 anti‑phishing inspect `Reply-To`
  independently of spam/spoof. **Whitelisting a permitted sender does *not*
  necessarily bypass impersonation policies** — they can still *hold* or
  *bounce* the message.
- The signal is amplified when `From == To` on an internal domain (see above):
  "internal sender, external reply‑to" is a textbook phishing shape.

**Test it cleanly (no code change):** set `CONTACT_DISABLE_REPLY_TO=1` in Vercel,
redeploy, and send a test.

- **Lands now →** Reply‑To mismatch was the trigger. Prefer adding a **Mimecast
  Impersonation Protect exception** (permit this sender / bypass reply‑to‑mismatch)
  and then re‑enable Reply‑To (`CONTACT_DISABLE_REPLY_TO=` blank) so staff keep
  one‑click reply — rather than permanently dropping it.
- **Still held →** Reply‑To was not the cause; focus on the `from == to`
  spoof/tenant‑policy fixes above (and check the Mimecast held/rejected log).

> If mail routes through **Mimecast**, check **Administration → Message Center →
> Held / Rejected & Bounced** and **Monitoring → Held Messages** for the exact
> policy that caught it (Spoofing / Impersonation Protect / Reply‑address
> mismatch). That log is the definitive answer.

## Current app configuration (correct for Path B)

Set in **Vercel → Project → Settings → Environment Variables** (the local
`.env` only affects `vercel dev`):

```
RESEND_FROM_EMAIL = noreply@msmeawards.org
RESEND_FROM_NAME  = Presidential MSME Awards
CONTACT_TO_EMAIL  = info@msmeawards.org
```

The API sets the visitor as `reply_to`, so staff can reply straight to the
enquirer even though the visible sender is `noreply@`.

---

## Step 0 — Confirm the diagnosis (2 minutes)

Using a Microsoft 365 **admin** account:

1. **Message trace** — Exchange admin center → *Mail flow → Message trace* →
   search sender `noreply@msmeawards.org` for the last 2 days. Disposition will
   read **Quarantined** or **FilteredAsSpam / Junk**, not *Delivered*.
2. **Quarantine** — <https://security.microsoft.com> → *Email & collaboration →
   Review → Quarantine* → filter sender `noreply@msmeawards.org`. The test
   emails are almost certainly here. Select them → **Release**.
3. Also check the **Junk Email** folder of `info@msmeawards.org`.

---

## Path B — Keep `noreply@msmeawards.org`, tell M365 to trust it

Do **B1** (fastest, purpose‑built) *or* **B3** (most surgical/robust). B2 is a
simple fallback. You do **not** need all three.

### B1 — Allow the spoof (Tenant Allow/Block List) ✅ recommended

<https://security.microsoft.com> → **Email & collaboration → Policies & rules →
Threat policies → Tenant Allow/Block Lists → Spoofed senders → + Add**

- **Spoofed user:** `noreply@msmeawards.org`
- **Sending infrastructure:** `amazonses.com`  *(Resend sends over Amazon SES)*
- **Spoof type:** External
- **Action:** **Allow**

> Tip: if any test mail has already arrived, use **Spoof intelligence insight**
> (same *Threat policies* page) instead — find the row for `msmeawards.org` /
> `amazonses.com`, and set **Allowed = Yes**. It auto‑fills the exact sending
> infrastructure M365 observed.

### B2 — Allowed sender (anti‑spam inbound policy) — simple fallback

<https://security.microsoft.com> → **Threat policies → Anti‑spam →
Anti‑spam inbound policy (Default)** → **Edit allowed and blocked senders and
domains** → **Allow senders** → add `noreply@msmeawards.org`.

> Broader/blunter than B1. Fine as a stopgap; prefer B1 or B3 long‑term.

### B3 — Transport rule that trusts only DKIM‑verified mail 🔒 most robust

Guarantees inbox delivery and is spoof‑proof, because only Resend can produce a
valid DKIM signature for `msmeawards.org`.

<https://admin.exchange.microsoft.com> → **Mail flow → Rules → + Add a rule →
Create a new rule**

- **Name:** `Trust Resend contact-form mail (DKIM-verified)`
- **Apply this rule if… (ALL of):**
  1. **The sender** → **domain is** → `msmeawards.org`
  2. **A message header** → **includes any of these words**
     - Header name: `Authentication-Results`
     - Value: `dkim=pass header.d=msmeawards.org`
- **Do the following:**
  - **Modify the message properties → set the spam confidence level (SCL) →
    Bypass spam filtering (-1)**
- (Optional) **Except if** → *The sender is located* → *Inside the organization*
  — so the rule only affects the external Resend path.
- **Mode:** Enforce. Save.

> Scoping the bypass to `dkim=pass header.d=msmeawards.org` is safe: an actual
> spoofer cannot generate a valid DKIM signature for your domain, so they can't
> match this rule.

---

## ✅ Path A (RECOMMENDED) — send from a sending subdomain

This is the cleanest, most durable fix. Because `send.msmeawards.org` is **not**
an accepted domain in the tenant (and *"Accept mail for all subdomains"* is
**off**), Microsoft treats it as an ordinary external sender — so the intra‑org
spoof classification never applies. No tenant‑policy change; can't be undone by a
future policy reset; unaffected by the Mimecast/M365 routing question.

1. **Resend → Domains → Add Domain:** `send.msmeawards.org`.
2. Publish the DNS records Resend shows for the subdomain (in the DNS zone for
   `msmeawards.org`):
   - **DKIM** — `resend._domainkey.send` (CNAME/TXT as Resend specifies)
   - **SPF/MX** for the subdomain (e.g. `send TXT "v=spf1 include:amazonses.com ~all"`)
   - the Return‑Path/`_dmarc.send` records if Resend lists them
   Wait for **Verified**.
3. **Vercel → Project → Settings → Environment Variables** (all environments):
   ```
   RESEND_FROM_EMAIL = noreply@send.msmeawards.org
   RESEND_FROM_NAME  = Presidential MSME Awards
   CONTACT_TO_EMAIL  = info@msmeawards.org
   ```
   **Redeploy** so the functions pick up the new values.
4. Submit the live form. `info@` receives it in the **inbox**; staff **Reply**
   still goes to the visitor (the API sets `Reply-To`).

No code change is required — the sender is fully env‑driven.

---

## Verify the fix

1. Submit the live contact form (or use Resend → *Emails* → send a test from
   `noreply@msmeawards.org` to `info@msmeawards.org`).
2. **Message trace** should now show **Delivered**.
3. The message should be in the **`info@` inbox** (not Junk/Quarantine).
4. In Resend → **Emails**, the row should show **Delivered** (not just the
   `200`/queued state in *Logs*).

Changes to Tenant Allow/Block List, anti‑spam policy, and transport rules
typically apply within a few minutes but can take up to ~30–60 min to fully
propagate across the tenant.

---

## Optional hardening (after Path B works)

- **Tighten DMARC:** once every legitimate sender is DKIM‑aligned, raise
  `_dmarc.msmeawards.org` from `p=none` to `p=quarantine` (optionally with
  `pct=` ramp and a `rua=` reporting mailbox). A stronger, aligned DMARC policy
  *improves* inbox placement for your own mail.
- **Resend webhooks:** add a webhook (Resend → *Webhooks*) for
  `email.delivered` / `email.bounced` / `email.complained` so the **true**
  delivery status is captured, instead of relying on the `200` queue ack.
