package com.scamlens.service;

import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class DemoService {

    public static class DemoSample {
        private String id;
        private String title;
        private String expectedCategory;
        private String sourceType;
        private String content;

        public DemoSample() {
        }

        public DemoSample(String id, String title, String expectedCategory, String sourceType, String content) {
            this.id = id;
            this.title = title;
            this.expectedCategory = expectedCategory;
            this.sourceType = sourceType;
            this.content = content;
        }

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public String getTitle() {
            return title;
        }

        public void setTitle(String title) {
            this.title = title;
        }

        public String getExpectedCategory() {
            return expectedCategory;
        }

        public void setExpectedCategory(String expectedCategory) {
            this.expectedCategory = expectedCategory;
        }

        public String getSourceType() {
            return sourceType;
        }

        public void setSourceType(String sourceType) {
            this.sourceType = sourceType;
        }

        public String getContent() {
            return content;
        }

        public void setContent(String content) {
            this.content = content;
        }
    }

    private final List<DemoSample> samples = new ArrayList<>();

    public DemoService() {
        initializeSamples();
    }

    private void initializeSamples() {
        // 1. Phishing
        samples.add(new DemoSample(
                "demo-1",
                "Bank Account Verification Lure",
                "Phishing",
                "SMS",
                "Dear customer, your bank account has experienced an unusual login attempt. Click the link below to login and update your account details immediately: http://login.secure-bank-update.xyz/auth?token=92847"
        ));

        // 2. OTP Theft
        samples.add(new DemoSample(
                "demo-2",
                "Urgent OTP Harvesting",
                "OTP and Credential Theft",
                "SMS",
                "Your card transaction of $850.00 is pending. Share your OTP immediately to verify your account or cancel this payment. Forward the code to 9876543210 right now."
        ));

        // 3. Fake Job Scam
        samples.add(new DemoSample(
                "demo-3",
                "Work-From-Home High Income Scam",
                "Fake Job Scams",
                "WhatsApp",
                "Exciting part-time job offer! Work from home earn 5000/day simply evaluating products. Guaranteed job placement. Pay registration fee for job of 500 rupees to confirm your slot. Contact HR on WhatsApp now: +18005550192"
        ));

        // 4. Lottery / Prize Scam
        samples.add(new DemoSample(
                "demo-4",
                "International Sweepstakes Winner",
                "Lottery and Prize Scams",
                "Email",
                "Congratulations you won! You have been selected as the lottery winner of $1,000,000 in our international annual lucky draw. To claim your prize, please send money for transfer fee and clearance fee ($250) to our treasury manager at bit.ly/claim-lotto"
        ));

        // 5. Financial Fraud / Crypto Scheme
        samples.add(new DemoSample(
                "demo-5",
                "Guaranteed Crypto Doubler",
                "Financial Fraud",
                "Social Media",
                "Exclusive crypto investment opportunity! Deposit money today and double your money within 48 hours guaranteed. Send wire transfer or Bitcoin to our verified wallet now to lock in 200% returns: http://192.168.1.55/invest"
        ));

        // 6. Impersonation (Courier Delivery)
        samples.add(new DemoSample(
                "demo-6",
                "Postal / Delivery Impersonation",
                "Impersonation",
                "SMS",
                "DHL Express: Your parcel on hold at our regional distribution center due to an incomplete delivery address. Package delivery failed. Visit http://dhl.parcel-track.cf/redelivery to update address and pay $1.99 redelivery fee."
        ));

        // 7. Impersonation (Streaming / Subscription)
        samples.add(new DemoSample(
                "demo-7",
                "Subscription Suspension Impersonation",
                "Impersonation",
                "Email",
                "Netflix Service Alert: Your Netflix subscription suspended due to billing payment failure. Click here to confirm your identity and update payment card CVV to avoid interruption: http://netflix.billing-portal.top/update"
        ));

        // 8. Urgency & Threat Scam
        samples.add(new DemoSample(
                "demo-8",
                "Legal Threat / Account Suspension",
                "Urgency and Threat Scams",
                "SMS",
                "FINAL NOTICE: Immediate action required! Your electricity service and bank account will be blocked within 24 hours. Legal action will be taken unless unpaid fee is cleared today. Call immediately at 1800-333-999."
        ));

        // 9. Suspicious Obfuscated URL / Punycode
        samples.add(new DemoSample(
                "demo-9",
                "Deceptive URL with Punycode & UserInfo",
                "Suspicious URL",
                "Email",
                "Security notification from PayPal support: Click https://paypal.com@xn--pypal-4ve.com/signin to review unauthorized activity on your account."
        ));

        // 10. Legitimate Security Warning (Negation Context)
        samples.add(new DemoSample(
                "demo-10",
                "Official Bank Security Warning",
                "Legitimate Security Advisory",
                "SMS",
                "Alert from State Bank: Never share your OTP, PIN, password or CVV with anyone. Bank officials will never ask for your confidential banking credentials. Beware of fraud and stay safe."
        ));

        // 11. Normal Everyday Conversation
        samples.add(new DemoSample(
                "demo-11",
                "Normal Casual Message",
                "Normal Communication",
                "WhatsApp",
                "Hey Alex, are we still meeting for lunch at 1 PM today? Let me know if the Italian cafe on Main Street works for you."
        ));

        // 12. Normal Business Transaction Receipt
        samples.add(new DemoSample(
                "demo-12",
                "Standard Order Confirmation",
                "Normal Communication",
                "Email",
                "Thank you for your order with Bookstore Inc. Your order #48920 has been confirmed and is scheduled to ship on Monday. Track your shipment anytime in your account dashboard."
        ));
    }

    public List<DemoSample> getAllSamples() {
        return samples;
    }

    public DemoSample getSampleById(String id) {
        return samples.stream()
                .filter(s -> s.getId().equalsIgnoreCase(id))
                .findFirst()
                .orElse(null);
    }
}
