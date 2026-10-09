"""Static recovery plan. Used when the AI is unavailable, so the panic flow never dead-ends."""

# action id -> (label shown to the user, steps) ; each step is (when, text)
ACTIONS = {
    "sent_money": "I sent money",
    "shared_otp": "I shared an OTP",
    "shared_pin": "I shared my UPI PIN, card PIN or CVV",
    "shared_password": "I shared a password or login",
    "shared_id": "I shared Aadhaar, PAN or other ID details",
    "clicked_link": "I clicked a link",
    "installed_app": "I installed an app or APK, or allowed screen sharing",
    "talked_to_caller": "I stayed on a call or video call with them",
}

_STEPS = {
    "sent_money": [
        ("now", "Call 1930 (National Cyber Crime Helpline) right away. Reporting quickly gives the best chance of freezing the money."),
        ("now", "Call your bank's official helpline (number on your card or the bank's official app) and ask them to block the transaction or account."),
    ],
    "shared_otp": [
        ("now", "Call your bank's official helpline and tell them an OTP was shared. Ask them to block cards and UPI on that account."),
    ],
    "shared_pin": [
        ("now", "Block the card or UPI ID through your bank's official app or helpline, then set a new PIN."),
    ],
    "shared_password": [
        ("now", "Change that password from a device you trust. If you use it elsewhere, change it there too."),
        ("today", "Turn on two-step verification for that account and log out of all other devices."),
    ],
    "shared_id": [
        ("today", "Watch your bank, SIM and credit reports for activity you did not do. Tell your bank that your ID details were shared."),
        ("week", "Check at your telecom provider that no new SIM cards were issued in your name."),
    ],
    "clicked_link": [
        ("now", "Do not enter any details on the page. If you already did, treat it as shared details and follow the steps above."),
        ("today", "Clear your browser history and cache, then run a security scan on your phone."),
    ],
    "installed_app": [
        ("now", "Switch on airplane mode, then uninstall the app. Remove screen-sharing apps such as AnyDesk or TeamViewer."),
        ("now", "Call your bank to block access, because the person may have seen your banking screens."),
        ("today", "Change your passwords from a different, clean device, then factory reset your phone if you can."),
    ],
    "talked_to_caller": [
        ("now", "End the call. Real police and agencies never arrest anyone over a video call and never ask for money to clear a case."),
        ("today", "Tell a family member or friend what happened, even if you feel embarrassed. Scammers rely on secrecy."),
    ],
}

_WHEN_ORDER = {"now": 0, "today": 1, "week": 2}

_ALWAYS = [
    ("today", "Report it on cybercrime.gov.in. Keep screenshots, phone numbers, transaction IDs and the time of each event."),
    ("today", "Do not reply to the scammer again and do not pay anything to \"recover\" lost money. Fake recovery agents are common."),
    ("week", "Keep checking your bank statements for the next few weeks."),
]


def build_static_plan(actions, details="", amount=""):
    """Return the same shape the AI returns, built deterministically."""
    chosen = [a for a in actions if a in _STEPS]
    steps = []
    seen = set()
    for a in chosen:
        for when, text in _STEPS[a]:
            if text not in seen:
                seen.add(text)
                steps.append({"when": when, "action": text})
    for when, text in _ALWAYS:
        steps.append({"when": when, "action": text})
    steps.sort(key=lambda s: _WHEN_ORDER[s["when"]])

    what = "; ".join(ACTIONS[a] for a in chosen) or "I was targeted by a suspected scam"
    lines = [
        "To the Cyber Crime Cell,",
        "",
        f"I am reporting a suspected online fraud. What happened: {what}.",
    ]
    if amount:
        lines.append(f"Amount lost: {amount}.")
    if details:
        lines.append(f"Details: {details}")
    lines += [
        "Date and time of incident: [fill in]",
        "Scammer's phone number, link or account: [fill in]",
        "Transaction ID / UTR number (if any): [fill in]",
        "My bank and account's last 4 digits: [fill in]",
        "",
        "I request that the transaction be flagged and the matter be investigated.",
    ]
    banner = (
        "If money has left your account, call 1930 now."
        if "sent_money" in chosen
        else "Act on the first steps now. Speed matters."
    )
    return {"urgency_banner": banner, "steps": steps, "complaint_summary": "\n".join(lines), "source": "built-in"}
