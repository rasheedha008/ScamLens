package com.scamlens.controller;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Controller
public class AwarenessController {

    public static class AwarenessTopic {
        private String id;
        private int number;
        private String title;
        private String icon;
        private String summary;
        private String fullExplanation;
        private List<String> warningSigns;
        private String realisticExample;
        private List<String> safetyProtocols;

        public AwarenessTopic() {
        }

        public AwarenessTopic(String id, int number, String title, String icon, String summary,
                              String fullExplanation, List<String> warningSigns,
                              String realisticExample, List<String> safetyProtocols) {
            this.id = id;
            this.number = number;
            this.title = title;
            this.icon = icon;
            this.summary = summary;
            this.fullExplanation = fullExplanation;
            this.warningSigns = warningSigns;
            this.realisticExample = realisticExample;
            this.safetyProtocols = safetyProtocols;
        }

        public String getId() { return id; }
        public int getNumber() { return number; }
        public String getTitle() { return title; }
        public String getIcon() { return icon; }
        public String getSummary() { return summary; }
        public String getFullExplanation() { return fullExplanation; }
        public List<String> getWarningSigns() { return warningSigns; }
        public String getRealisticExample() { return realisticExample; }
        public List<String> getSafetyProtocols() { return safetyProtocols; }
    }

    private final List<AwarenessTopic> topics = new ArrayList<>();

    public AwarenessController() {
        initializeTopics();
    }

    private void initializeTopics() {
        // Topic 1
        topics.add(new AwarenessTopic(
                "phishing", 1, "What is Phishing?", "fa-solid fa-fish-fins",
                "Phishing is a deceptive social engineering attack where attackers impersonate trusted institutions to steal sensitive data.",
                "In a phishing attack, malicious actors send fraudulent communications (emails, text messages, or direct messages) disguised as legitimate organizations such as banks, technology providers, or government departments. Their goal is to deceive recipients into providing passwords, credit card numbers, or social security details on lookalike websites.",
                Arrays.asList(
                        "Generic greetings like 'Dear Customer' instead of your real name.",
                        "Spelling inconsistencies or slightly modified sender domain names (e.g., support@paypa1.com).",
                        "High urgency warning that your account is about to be terminated or billed unexpectedly."
                ),
                "\"Dear Apple user, your iCloud account has been locked due to unauthorized access. Click here immediately to verify your identity and restore access.\"",
                Arrays.asList(
                        "Never click links sent in unsolicited emails or SMS alerts.",
                        "Manually navigate to the genuine website by typing its verified URL in your browser.",
                        "Enable multi-factor authentication (MFA) on all critical accounts."
                )
        ));

        // Topic 2
        topics.add(new AwarenessTopic(
                "otp-scams", 2, "How OTP Scams Work", "fa-solid fa-key",
                "OTP (One-Time Password) theft tricks victims into giving up their second authentication factor during transactions.",
                "One-Time Passwords are the final security barrier protecting your bank accounts and digital profiles. Fraudsters frequently call or message victims pretending to be bank executives, courier agents, or security specialists. They claim they need the OTP to cancel an unauthorized transaction, reverse an incorrect charge, or verify package delivery.",
                Arrays.asList(
                        "Caller claims to be a bank official who 'needs your OTP to stop a fraudulent transaction.'",
                        "SMS requests you to 'forward the 6-digit code received on your phone.'",
                        "Caller asks you to share your screen or install remote access tools like AnyDesk or TeamViewer."
                ),
                "\"State Bank Alert: An unauthorized payment of $450 was attempted. To decline this transaction, immediately read back the 6-digit OTP sent to your mobile phone.\"",
                Arrays.asList(
                        "Understand that banks, government agencies, and tech companies will NEVER ask for your OTP.",
                        "Read the exact text of every OTP SMS carefully—it clearly specifies the amount and destination.",
                        "Never read out or type an OTP into any website you did not independently navigate to."
                )
        ));

        // Topic 3
        topics.add(new AwarenessTopic(
                "fake-jobs", 3, "How Fake Job Scams Work", "fa-solid fa-briefcase",
                "Job scams prey on employment seekers by offering high salaries for minimal work, then demanding upfront fees.",
                "In recruitment fraud, scammers contact job seekers via WhatsApp, Telegram, LinkedIn, or SMS offering flexible 'work from home' positions. These tasks often involve 'liking YouTube videos', 'submitting hotel reviews', or 'data entry'. After paying small initial bonuses, the scammers demand large 'security deposits', 'equipment fees', or 'tax clearance' to release accumulated earnings.",
                Arrays.asList(
                        "Extravagant income promises like 'Earn $500/day working 1 hour from home.'",
                        "The recruiter insists on conducting interviews only via Telegram or WhatsApp.",
                        "The employer requires you to pay upfront for registration, laptop shipping, or training."
                ),
                "\"Hello! Amazon recruitment team has selected your resume for part-time online product review. Earn $200-$800 daily. Pay $50 registration fee to begin onboarding.\"",
                Arrays.asList(
                        "Legitimate employers never demand upfront application, training, or equipment fees.",
                        "Verify job openings directly on the official company careers website.",
                        "Be suspicious of any recruiter using free email addresses like Gmail or Yahoo."
                )
        ));

        // Topic 4
        topics.add(new AwarenessTopic(
                "lottery-scams", 4, "How Lottery Scams Work", "fa-solid fa-trophy",
                "Advance-fee lottery scams inform targets that they won an unentered raffle, requiring taxes before payout.",
                "Lottery and prize scams inform victims that their email address, mobile number, or social media profile was chosen in an international lucky draw. To claim the millions of dollars, the victim is instructed to transfer relatively small amounts for 'customs clearance', 'foreign exchange tax', or 'insurance fees'. Once money is sent, the scammers disappear or demand more fees.",
                Arrays.asList(
                        "Notification claiming you won a contest, lottery, or grant you never entered.",
                        "Urgent demand to send money via wire transfer, gift cards, or cryptocurrency to 'unlock' funds.",
                        "Sender uses excessive official-sounding stamps, fake certificates, or claims United Nations endorsement."
                ),
                "\"Congratulations! Your mobile number won 1st prize of $1,500,000 in the Global Telecom Lucky Draw. Transfer $350 processing fee to release your banker's check.\"",
                Arrays.asList(
                        "Remember the golden rule: You cannot win a lottery you did not buy a ticket for.",
                        "Real lotteries deduct taxes from winnings; they never demand advance cash transfers.",
                        "Never pay upfront money to collect a supposed prize."
                )
        ));

        // Topic 5
        topics.add(new AwarenessTopic(
                "suspicious-urls", 5, "How to Identify Suspicious URLs", "fa-solid fa-link",
                "Scammers construct misleading domain names, URL shorteners, and lookalike characters to deceive users.",
                "Attackers register domain names that visually mimic trusted brands using techniques like typo-squatting (e.g., netf1ix.com), homoglyphs with Cyrillic characters (punycode), and subdomain deception (e.g., paypal.com.verify-login.xyz). They also leverage URL shorteners (like bit.ly) to hide the real target.",
                Arrays.asList(
                        "Use of generic URL shorteners in messages from supposed corporate entities.",
                        "IP addresses in the address bar (e.g., http://192.168.1.5/login) instead of genuine domain names.",
                        "Uncommon domain extensions (.xyz, .top, .buzz, .cf) used for financial or utility services."
                ),
                "\"http://appleid.apple.com.manage-security-check.xyz/login?token=89234\"",
                Arrays.asList(
                        "Inspect the registered domain: read backwards from the first single slash '/'.",
                        "Check for HTTPS and verify browser security certificate details.",
                        "Use ScamLens URL analysis to passively scan links before interacting."
                )
        ));

        // Topic 6
        topics.add(new AwarenessTopic(
                "impersonation", 6, "How Impersonation Scams Work", "fa-solid fa-user-secret",
                "Fraudsters pose as trusted institutions, government officials, or delivery services to exploit authority.",
                "Impersonation scams exploit trust, respect for authority, or curiosity. Common personas include courier services (postal packages held for non-payment of small customs fees), utility providers (power will be disconnected tonight), law enforcement (arrest warrants for tax fraud), and tech support (renewals for anti-virus services).",
                Arrays.asList(
                        "Unsolicited messages regarding parcel deliveries when you haven't ordered anything.",
                        "Threats from law enforcement or tax offices demanding payment over the phone.",
                        "Sudden emails about invoices or subscriptions you never registered for."
                ),
                "\"FedEx Notice: Your delivery #FX-9821 is suspended at depot due to unpaid $2.45 tax. Click link to pay and reschedule delivery within 12 hours.\"",
                Arrays.asList(
                        "Contact the organization independently using the official phone number on their verified website.",
                        "Never make payments on unknown links sent via SMS.",
                        "Delivery services do not cancel deliveries without formal postal notice."
                )
        ));

        // Topic 7
        topics.add(new AwarenessTopic(
                "fake-payments", 7, "How to Identify Fake Payment Requests", "fa-solid fa-money-bill-wave",
                "Attackers use fake payment screenshots, reverse payment requests, and overpayment scams to steal money.",
                "On online marketplaces (OLX, Facebook Marketplace, eBay), scammers target sellers by sending 'payment links' where clicking or scanning a QR code actually deducts money from the seller's account rather than depositing it. They also send forged banking SMS notifications claiming funds have been transferred.",
                Arrays.asList(
                        "Buyer insists you scan a QR code or enter your UPI PIN to 'receive' money.",
                        "Buyer sends a manipulated screenshot showing payment before it reflects in your bank app.",
                        "Buyer 'accidentally' overpays and demands an immediate refund of the difference."
                ),
                "\"I have sent $500 for your furniture. Please scan this QR code and enter your banking PIN to accept the credited payment into your bank.\"",
                Arrays.asList(
                        "Remember: You NEVER need to enter your PIN or scan a QR code to RECEIVE money.",
                        "Only trust your official bank mobile app or statement to verify deposit receipt.",
                        "Reject any buyer demanding you refund overpayments through gift cards or wire transfers."
                )
        ));

        // Topic 8
        topics.add(new AwarenessTopic(
                "protect-personal-data", 8, "How to Protect Personal Information", "fa-solid fa-shield-halved",
                "Guarding your Personally Identifiable Information (PII) is your first defense against identity theft.",
                "Personally Identifiable Information—such as your full legal name, date of birth, mother's maiden name, Aadhaar/SSN number, and primary phone number—can be leveraged by identity thieves to open credit accounts, bypass security questions, and execute SIM swap frauds.",
                Arrays.asList(
                        "Forms or quizzes asking for personal history, childhood pets, or favorite cars.",
                        "Unsolicited requests to upload photos of government ID cards to Google Forms or third-party sites.",
                        "Over-sharing travel dates, home addresses, or phone numbers on public social media profiles."
                ),
                "\"Fill out this quick survey to win an iPhone! Please provide your full name, date of birth, home address, and mother's maiden name.\"",
                Arrays.asList(
                        "Be selective about the personal information you share online.",
                        "Set social media profiles to private and restrict who can view your friend list and contact info.",
                        "Use unique, complex passwords for every platform with a trusted password manager."
                )
        ));

        // Topic 9
        topics.add(new AwarenessTopic(
                "after-suspicious-message", 9, "What to Do After Receiving a Suspicious Message", "fa-solid fa-triangle-exclamation",
                "Knowing the immediate step-by-step containment protocol protects your digital identity and finances.",
                "When you receive a suspicious message, your immediate reaction dictates your safety. Panicking or acting impulsively is precisely what threat actors rely upon. Following a disciplined response checklist ensures that threats are contained, reported, and blocked before harm occurs.",
                Arrays.asList(
                        "Do NOT click any links, open attachments, or dial phone numbers enclosed in the message.",
                        "Do NOT reply with insults, test messages, or requests to 'unsubscribe' (which confirms your number is active).",
                        "Take a screenshot for reporting evidence if needed."
                ),
                "Step-by-step incident response: 1. Stop and do not interact. 2. Scan content with ScamLens. 3. Block and report sender. 4. Change passwords if credentials were entered.",
                Arrays.asList(
                        "Scan the suspicious text in ScamLens to obtain a detailed heuristic analysis.",
                        "Use your device's native 'Report Spam & Block' feature.",
                        "If banking credentials were entered, contact your bank's 24/7 fraud helpline immediately to freeze your account."
                )
        ));

        // Topic 10
        topics.add(new AwarenessTopic(
                "cyber-practices", 10, "Basic Cybersecurity Safety Practices", "fa-solid fa-laptop-code",
                "Foundational digital hygiene habits that protect against over 90% of cyber threats.",
                "Cyber hygiene is the ongoing practice of maintaining your digital systems and personal habits to minimize attack surfaces. By instituting fundamental cybersecurity practices, individuals and families can protect their finances, privacy, and digital assets.",
                Arrays.asList(
                        "Reusing the same password across personal email, banking, and shopping websites.",
                        "Ignoring operating system and browser security updates for weeks.",
                        "Connecting to unsecured public Wi-Fi networks without a reliable VPN."
                ),
                "Best practices in action: Long unique passphrases + MFA authenticator app + automatic software updates + regular data backups.",
                Arrays.asList(
                        "Adopt Multi-Factor Authentication (MFA/2FA) utilizing authenticator apps rather than plain SMS.",
                        "Keep your operating system, browser, and mobile apps up to date with automated security patches.",
                        "Perform regular offline backups of essential files and documents."
                )
        ));
    }

    @GetMapping("/awareness")
    public String awarenessPage(Authentication authentication, Model model) {
        boolean isAuthenticated = (authentication != null && authentication.isAuthenticated() &&
                !"anonymousUser".equals(authentication.getPrincipal()));
        model.addAttribute("isAuthenticated", isAuthenticated);
        model.addAttribute("topics", topics);
        return "awareness";
    }
}
