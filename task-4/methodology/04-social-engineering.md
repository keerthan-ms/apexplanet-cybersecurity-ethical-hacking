# 04 — Social Engineering & Phishing Simulation (Methodology)

Brief for this deliverable: create a phishing simulation page and demonstrate
awareness training for phishing detection.

---

## Authorisation first

**A phishing simulation against people who have not consented is harmful, and
in many jurisdictions it is illegal.** Sending unsolicited messages that
impersonate a trusted organisation, or that lead a recipient toward a credential
entry page, engages computer-misuse and fraud law (in the UK: the Computer
Misuse Act 1990 and the Fraud Act 2006; in the US: the CFAA plus wire-fraud
statutes; in the EU: national fraud and computer-crime codes). Even where an
employer *can* lawfully simulate phishing on its own staff, doing it badly
causes real damage: panic, damaged trust, and disciplinary fallout for someone
who clicked at 07:00 without coffee.

**What this lab actually is.** The Task 4 phishing simulation is a page that
runs locally on this machine, for demonstration and inspection only. **It is
not sent to anyone.** No message is delivered, no data is collected from any
person, no domain is registered, no email is spoofed. Its purpose is to let a
reader examine the mechanics of a phishing page and the mechanics of
detecting one.

**What a real simulation requires — in this order, in writing:**

1. **Executive and legal approval.** Named sponsor, and sign-off from
   legal/HR (and works-council or union consultation where it applies —
   some jurisdictions require it before staff may be tested at all).
2. **Agreed scope.** Which departments or the whole organisation; who is
   explicitly excluded (board members under investigation, staff on leave,
   recently joined, under disciplinary process, or known to be in distress);
   whether executives may be included at all.
3. **A safety net in advance.** IT service desk briefed and staffed for the
   wave of reports, a published "how do I know this is a simulation?" route,
   and an out-of-hours policy so messages do not sit unread over a weekend
   and get opened by someone on a phone with no way to verify.
4. **No credential capture.** The simulation landing page must not store what
   people type. Record the *fact* of submission (a timestamp and a random
   one-time code), never the secret. A simulation that harvests real
   passwords has created a genuine incident in place of a training exercise.
5. **No malware, no payloads, no persistence.** Clicking should land on a
   "you were part of a training exercise" page, full stop.
6. **Duty of care in reporting.** Results are reported by team and role,
   never by individual, in anything that leaves the security team.

Without all six, you are not running a simulation — you are running a
phishing campaign on your own colleagues.

---

## Anatomy of a phishing message

Every phishing message is a set of social-engineering cues wrapped in
technically forged or abused signals. Learn to take it apart in this order.

### 1. Sender spoofing

- **Display name vs envelope sender.** The `From:` display name is free text.
  A mail client shows "IT Helpdesk <it-helpdesk@apexplanet.in>"; the actual
  sending identity — visible in the message headers as `Return-Path:` and the
  `smtp.mailfrom=` in the authentication results — may be
  `x9k2z@mail-rust.example.net`. Clients show the name; filters authenticate
  the envelope. They can disagree.
- **Lookalike domains (typosquats).** `apexplanet-secure.com`,
  `apexplanet.co.in` (note: real TLD), `apexplanet.in.com`,
  `apexplanet-support.net`. Each is a different domain that a filter can and
  should catch once DMARC is enforced.
- **Unicode homoglyphs.** Characters from another alphabet that render
  identically. In code fences so they cannot be mistaken for the real thing:

  ```text
  аpexplanet.in        <- first "a" is Cyrillic а (U+0430), not Latin a
  аррӏе.com             <- Cyrillic а р р ӏ е — looks like "apple.com"
  gооgle.com           <- Cyrillic о о
  ```

  Punycode makes them visible: a browser converts a homoglyph domain to
  `xn--pypal-4ve.com` before you can type it. Hover the link or paste the
  domain into a punycode converter to see the true form.

- **Reply-To hijack.** Message arrives from a lookalike domain but
  `Reply-To:` points at an attacker's inbox, so you reply to them after
  "verifying" the sender.
- **Compromised legitimate accounts.** The worst case: a real, authenticated
  sender who has been phished. SPF, DKIM and DMARC all pass, because the
  message really is from them. Nothing about header authentication protects
  you here — only content and context do.

### 2. Urgency and authority cues

- Time pressure: "Your account will be suspended in 24 hours", "invoice
  overdue — legal action pending", "unusual sign-in — confirm now".
- Authority: the CEO, the bank, a regulator, "IT support".
- Fear and consequence: payroll error, account lockout, package
  non-delivery.
- Reward: bonus, refund, prize, "document shared with you".
- Modern variants that exploit *process*, not panic: an "MFA approval
  prompt" pushed repeatedly until you accept it (MFA fatigue), a "missed
  call" voicemail attachment, a Teams/Slack message from a "colleague".

The technique is called **pretext**: a believable story that explains why you
are being asked, why now, and why the normal channel is not being used.

### 3. The mismatched link

The single most reliable mechanical check. The link text says
`https://portal.apexplanet.in/reset`; where does it actually go?

Ways to check before clicking:

```powershell
# Windows (PowerShell 5.1, on this machine): resolve a domain without visiting it
Resolve-DnsName suspicious-domain.example -Type A

# Follow a shortened/redirecting link and print the FINAL URL, without a browser
$r = Invoke-WebRequest -Uri "https://bit.ly/abc123" -MaximumRedirection 5 -UseBasicParsing
$r.BaseResponse.ResponseUri.AbsoluteUri
```

```bash
# Kali / macOS / Linux: same idea with curl — print final URL and the redirect chain
curl -s -o /dev/null -w '%{url_effective}\n' -L https://bit.ly/abc123
curl -sIL -o /dev/null -w '%{http_code} %{url_effective}\n' https://bit.ly/abc123
```

In an email client: hover the link and read the status-bar target; or open
the message source and read the raw `href`. Check for:

- a different domain entirely,
- a real brand's URL on a *subdomain of the attacker's* domain
  (`apexplanet.in.attacker-example.net`),
- a redirect chain that ends somewhere unexpected,
- IP-address URLs, URL shorteners, or a bare path with an odd port
  (`https://192.0.2.5:8443/`),
- a URL that is correct but a page that is not (an almost-perfect login
  clone on a different host, reached from the correct-looking link).

### 4. Attachment weaponisation

- **Macro-enabled Office files** (`.docm`, `.xlsm`, sometimes `.rtf`) with an
  instruction to "Enable Content" or "Enable Editing". Macros are code; the
  document is the loader.
- **Archives containing executables** (`.zip` → `.exe`), and disc images
  (`.iso`, `.img`, `.lnk`) which historically bypassed the "downloaded from
  the internet" mark and its warnings.
- **OneNote, HTML and PDF attachments** that embed a hyperlink to a hosted
  phishing page instead of carrying a payload.
- A file named `invoice_2026.html` or `Payment_Details.pdf.html` — the
  double extension works when the client hides it.

Treat unexpected attachments from external senders as hostile until verified
out of band, whatever they claim to be.

### 5. Content tells

- Generic greeting ("Dear Customer", "Dear User") where your name is known.
- Grammar and spelling errors, or phrasing that reads like a translation.
- Requests that bypass normal process: change bank details, buy gift cards,
  approve an urgent payment, share a code, install software.
- A mismatch between the claimed organisation and the writing style of an
  internal message.

---

## How to detect one — a numbered checklist

Print this for non-experts; it is designed to be followed under time pressure.

1. **Slow down at the moment of the cue.** Urgency is the load-bearing wall
   of the pretext. Any message that pressures you to act *now* has just
   earned your full suspicion.
2. **Hover before you click.** Put the pointer on every link and read the
   real destination in the status bar. Links in images or "buttons" — hover
   those too.
3. **Check the actual domain, character by character.** The registered domain
   is the last two labels before the path (`portal.apexplanet.in` →
   `apexplanet.in`). Look for extra labels before it, hyphens, homoglyphs,
   and unusual TLDs (`.xyz`, `.top`, `.click`, `.zip`).
4. **Verify out of band.** Contact the sender through a *known-good* channel
   you found yourself — not a phone number or link in the message. For
   anything involving money, payroll or credentials, no exceptions.
5. **Look for spelling and greeting anomalies.** Wrong logo, wrong domain in
   the footer, "Dear Customer" from someone who knows your name, a different
   signing-off team than usual.
6. **Be suspicious of unexpected attachments.** Especially Office files
   asking you to enable content, archives containing programs, and anything
   from a sender you do not normally receive files from.
7. **Do not treat the padlock as a safety signal.** TLS means the connection
   to *that host* is encrypted and the certificate matched the domain — it
   says nothing about who owns the host or whether it is trustworthy.
   Attackers get free certificates for phishing domains every day. A padlock
   proves confidentiality, not honesty.
8. **Report, do not just delete.** If you report, the security team can
   purge it from every mailbox; if you only delete it, it stays in everyone
   else's. Reporting is never punished, even when you clicked.

---

## Simulation design

### What a legitimate exercise measures

The purpose is a **baseline and a trend**, not a hunt for culprits.

| Metric | Definition | Why it matters |
|---|---|---|
| **Report rate** | Recipients who used the official report button / forwarded to the SOC, ÷ recipients delivered | The primary KPI. It measures the behaviour you actually want |
| **Click rate** | Unique recipients who clicked the simulation link ÷ delivered | Secondary; useful, but alone it teaches "don't click" instead of "report" |
| **Credential submission rate** | Submissions recorded on the landing page ÷ delivered | Only if the design records the event without capturing secrets |
| **Median time-to-report** | Median minutes between delivery and the first report | The best predictor of how fast a real incident would be noticed |
| **Repeat click rate** | Participants who click in a second wave ÷ those who clicked in the first | Measures whether training changed behaviour, not whether a group is "bad" |

Deliberately **do not** rank individuals, publish league tables of names, or
tie results to individual performance reviews. Public shaming raises
concealment, not security: the next click goes unreported because reporting
now carries humiliation. Results belong to teams and roles, because that is
the level at which process and tooling fixes are made.

### The right response, and what to train

The correct human response to a suspected phish is **report, do not click**
— not "work out whether it is real". Teach the report button first, the
checklist second. Someone who reports a genuine message costs the SOC ten
minutes; someone who investigates alone costs the organisation an incident.

### The follow-up training loop

1. **Immediate, in-the-moment page.** A recipient who clicked sees a short
   explanation of the cues they could have checked — immediately, while the
   experience is live. This is worth more than any annual course.
2. **Short targeted training.** Two to five minutes, focused on the
   technique used in the wave (lookalike domains, MFA fatigue, invoice
   fraud), not a generic annual module.
3. **Fix the environment, not just the people.** If the wave worked because
   lookalike domains pass DMARC, enforce DMARC (`p=reject`). If it worked
   because of MFA prompt spam, move to number-matching/phishing-resistant
   MFA. If it worked because users could not report easily, fix the report
   button.
4. **Measure the next wave.** Report rate up and click rate down at the next
   simulation, at similar difficulty, is real evidence of improvement.
5. **Escalation path for genuine risk.** Anyone who submitted credentials
   gets their password reset and a quiet, blameless conversation —
   confidentially, never announced.

---

## Indicators that an email filter should catch

Technical authentication exists to answer one question: **was this message
really sent by the domain it claims to be from?** Three mechanisms, checked
in order of what they prove.

### SPF — Sender Policy Framework

- A DNS TXT record on the domain listing which IP addresses / hosts are
  allowed to send mail for it: `apexplanet.in. TXT "v=spf1 include:_spf.
  google.com -all"`.
- The receiving server checks the *envelope* sender's domain
  (`MAIL FROM` / `Return-Path`) against that list, and records the result
  in the headers as `spf=pass`, `spf=fail`, `spf=softfail`.
- **What it proves:** "this IP was authorised by the domain owner to send as
  the envelope sender".
- **What it does not prove:** anything about the *visible* `From:` name and
  address — that is DMARC's job. And `-all` vs `~all` matters: a softfail
  (`~all`) is a hint, a hardfail (`-all`) is an instruction.

### DKIM — DomainKeys Identified Mail

- The sending server signs selected headers (`From`, `Subject`, `Date`, body)
  with a private key; the public key is published in DNS at
  `selector1._domainkey.apexplanet.in`.
- The receiver verifies the signature and records `dkim=pass` with
  `header.d=<signing domain>`.
- **What it proves:** "the headers I signed have not been altered in transit,
  and whoever sent this holds the private key for that domain".
- **What it does not prove:** that the signer is the same domain shown in
  `From:` — unless DMARC alignment confirms it.

### DMARC — Domain-based Message Authentication, Reporting & Conformance

- A DNS record at `_dmarc.apexplanet.in`: `v=DMARC1; p=reject; rua=
  mailto:dmarc@apexplanet.in`.
- It ties the two together: it requires SPF or DKIM to **align** with the
  *visible* `From:` domain, applies a policy (`none` / `quarantine` /
  `reject`), and can request aggregate reports of what is failing.
- **What it proves/does:** with `p=reject`, unauthenticated mail claiming
  your domain should be refused at the border, which is the control that
  stops external typosquats and display-name spoofing of your brand.
- **What it does not prove:** anything about mail sent from a compromised
  legitimate account — that mail passes SPF, DKIM and DMARC, because it is
  genuinely from the domain.

### Where to look: header inspection

Every mail client can show the full headers; the interesting lines are:

```text
Return-Path: <x9k2z@mail-rust.example.net>     <- who actually sent it
Received: from mta123.example.net (…)
          by mx1.apexplanet.in …
          with ESMTPS …
Authentication-Results: mx1.apexplanet.in;
          spf=fail smtp.mailfrom=apexplanet.in.secure-billing.xyz;
          dkim=fail header.d=secure-billing.xyz;
          dmarc=fail header.from=apexplanet.in
From: "IT Helpdesk" <it-helpdesk@apexplanet.in>   <- what your client shows
Reply-To: it-support@secure-billing.xyz            <- where your reply would go
Message-ID: <a91c2f@secure-billing.xyz>
```

Reading it: the visible sender claims `apexplanet.in`, but the envelope,
DKIM domain, and Message-ID all point at `secure-billing.xyz`, and all three
authenticators fail. That is a textbook spoof — visible in ten seconds by
anyone who opens the headers.

Checking the same signals at the domain level (read-only DNS, safe to run
anywhere):

```powershell
Resolve-DnsName -Type TXT apexplanet.in              # SPF record
Resolve-DnsName -Type TXT _dmarc.apexplanet.in       # DMARC policy
Resolve-DnsName -Type TXT selector1._domainkey.apexplanet.in   # DKIM key
```

```bash
dig TXT apexplanet.in +short
dig TXT _dmarc.apexplanet.in +short
dig TXT selector1._domainkey.apexplanet.in +short
```

In Outlook: File → Options → the message → `Internet Headers`. In a
text-based client: view the full/raw source. In Gmail (web): Show original.
Teach people to look at `Authentication-Results` first — it is the
summarised verdict line written by their own mail server.

**Final point for the training material:** header authentication stops
*impersonation of a domain*. It does not stop a convincing message from a
real account, a message that passes all three checks and still asks you to
pay an invoice, or a link to a brand-new phishing domain that was registered
an hour ago. That is why detection still ends with a human decision, and why
the human's default action is to report.
