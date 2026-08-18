# Sample emails

Five synthetic `.eml` files for trying the analyzer. Every message, address,
domain and attachment here was written for this repository — none of it is
real mail. The ZIP in sample 05 contains a plain text file; the `.exe` name is
the point, not the content.

Upload any of these on the main page. The results below were produced with all
optional network lookups **disabled** (offline mode); with reverse DNS, ASN
and RDAP enabled the sending-server rows gain live enrichment and scores can
rise further.

| Sample | What it demonstrates | Artifact flags raised | Offline score |
|---|---|---|---|
| `01-clean-newsletter.eml` | A benign baseline — nothing fires | none | 0 (low) |
| `02-display-name-spoof.eml` | Display name impersonates the victim's own IT helpdesk while the real sender is elsewhere; Reply-To diverts to consumer webmail; "Re:" subject with no thread headers | `display_name_domain_mismatch`, `freemail_reply_target`, `reply_to_differs_from_sender`, `reply_prefix_without_thread_headers` | 6 (low) |
| `03-homograph-sender.eml` | Sender domain mixes Cyrillic into a Latin name (`exаmple-bank.com`) — visually identical, technically different | `homoglyph_sender_domain` | 9 (low) |
| `04-bcc-delivery.eml` | `Delivered-To` names a mailbox absent from To/Cc — the message arrived via BCC | `possible_bcc_delivery`, `reply_prefix_without_thread_headers` | 0 (low) |
| `05-zip-double-extension.eml` | ZIP attachment containing `invoice_8841.pdf.exe` — the classic double-extension lure | attachment flagged suspicious | 12 (low) |

Scores are intentionally modest: these files exercise header and attachment
signals in isolation, and the analyzer's trust model refuses to score anything
an attacker could fake by editing the file. Real phishing usually stacks these
signals with URL and content indicators, which is when scores climb.
