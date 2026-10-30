import re

class ScamDetector:
    def __init__(self):
        # Category patterns and weights
        self.rules = {
            "urgent_payment": {
                "weight": 25,
                "title": "Urgent Financial Action Required",
                "patterns": [
                    r"act immediately", r"urgent action required", r"account (will be|has been) suspended",
                    r"immediate payment", r"pay within \d+ hours?", r"wire transfer immediately",
                    r"avoid penalty", r"legal action", r"warrant for your arrest", r"lawsuit"
                ],
                "explanation": "Scammers often create artificial urgency to induce panic and prevent logical evaluation."
            },
            "lottery_prize": {
                "weight": 25,
                "title": "Unrealistic Prize / Reward Claim",
                "patterns": [
                    r"you have won", r"congratulations!? you('re| are) selected", r"claim your prize",
                    r"lottery winner", r"million dollars", r"gift card winner", r"reward waiting"
                ],
                "explanation": "Unsolicited claims of large prizes or rewards are almost universally fraudulent."
            },
            "bank_verification": {
                "weight": 20,
                "title": "Suspicious Bank / Verification Request",
                "patterns": [
                    r"verify your (bank|account|details)", r"unauthorized transaction", r"suspicious activity detected",
                    r"account locked", r"security alert", r"update your billing information"
                ],
                "explanation": "Legitimate institutions rarely ask users to verify sensitive details via direct unverified links."
            },
            "credential_harvesting": {
                "weight": 30,
                "title": "OTP / Credential Solicitation",
                "patterns": [
                    r"share (your|the) (otp|one time password|pin|code)", r"send your password",
                    r"do not share this code except", r"verification code is"
                ],
                "explanation": "No legitimate organization will ever ask you to disclose your one-time passwords (OTPs) or PINs."
            },
            "job_scam": {
                "weight": 15,
                "title": "Unrealistic Job / Income Offer",
                "patterns": [
                    r"work from home.*make \$\d+", r"earn \$\d+ (a day|per hour)", r"part-time job hiring",
                    r"no experience required.*daily payout", r"telegram for job info", r"whatsapp recruiter"
                ],
                "explanation": "Unsolicited high-paying job offers requiring minimal effort or upfront payments are common scams."
            },
            "investment_crypto": {
                "weight": 20,
                "title": "High-Yield Investment / Crypto Promise",
                "patterns": [
                    r"guaranteed return", r"double your (money|bitcoin|crypto)", r"risk-free investment",
                    r"crypto profit", r"trade signal", r"passive income guaranteed"
                ],
                "explanation": "Guaranteed financial returns in volatile markets like crypto or forex indicate Ponzi schemes or scams."
            },
            "impersonation": {
                "weight": 15,
                "title": "Brand / Authority Impersonation",
                "patterns": [
                    r"official notification", r"customer support team", r"helpdesk officer",
                    r"usps delivery failed", r"fedex parcel delayed", r"amazon order problem", r"irs refund"
                ],
                "explanation": "Scammers frequently impersonate trusted brands, delivery services, or government agencies."
            }
        }

        # URL specific checks
        self.url_shorteners = ['bit.ly', 'tinyurl.com', 'is.gd', 'buff.ly', 'ow.ly', 't.co', 'goo.gl', 'cutt.ly', 'rb.gy']

    def analyze_urls(self, text):
        indicators = []
        urls = re.findall(r'https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?', text)
        
        # Clean URLs
        cleaned_urls = []
        for u in urls:
            u_clean = u.rstrip('.,;)!?')
            if u_clean:
                cleaned_urls.append(u_clean)

        total_url_score = 0

        for url in cleaned_urls:
            url_score = 0
            reasons = []

            # 1. IP Address URL
            if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                url_score += 25
                reasons.append("Uses a raw IP address instead of a domain name.")

            # 2. URL Shortener
            if any(shortener in url.lower() for shortener in self.url_shorteners):
                url_score += 15
                reasons.append("Uses a URL shortener service which hides the true destination.")

            # 3. HTTP instead of HTTPS
            if url.startswith('http://'):
                url_score += 10
                reasons.append("Uses unencrypted HTTP connection rather than secure HTTPS.")

            # 4. Excessive Subdomains or Suspicious Top Level Domains
            domain_part = url.split('/')[0].replace('https://', '').replace('http://', '')
            subdomains = domain_part.split('.')
            if len(subdomains) > 3:
                url_score += 15
                reasons.append("Contains excessive subdomains, often used to mimic brand names.")

            suspicious_tlds = ['.xyz', '.top', '.club', '.work', '.click', '.loan', '.vip', '.online', '.site']
            if any(domain_part.endswith(tld) for tld in suspicious_tlds):
                url_score += 15
                reasons.append("Uses a low-cost Top-Level Domain frequently associated with spam.")

            # 5. Misleading brand names in URL (e.g. paypal-security-update.com)
            brand_keywords = ['paypal', 'amazon', 'apple', 'google', 'bank', 'netflix', 'microsoft']
            for brand in brand_keywords:
                if brand in domain_part and not domain_part.endswith(f"{brand}.com"):
                    url_score += 20
                    reasons.append(f"Contains brand name '{brand}' in a suspicious domain layout.")
                    break

            if url_score > 0:
                total_url_score += url_score
                indicators.append({
                    "category": "Suspicious URL Structure",
                    "title": f"Flagged URL: {url[:30]}...",
                    "weight": min(url_score, 30),
                    "explanation": f"URL analysis revealed risk factors: {' '.join(reasons)}"
                })

        return min(total_url_score, 35), indicators

    def analyze_message(self, message):
        if not message or not message.strip():
            return {
                "score": 0,
                "level": "Low",
                "indicators": [],
                "recommendations": ["No text provided for analysis."]
            }

        text_lower = message.lower()
        detected_indicators = []
        category_scores = {}

        # 1. Rule Pattern Matching
        for cat_key, rule in self.rules.items():
            for pattern in rule["patterns"]:
                if re.search(pattern, text_lower):
                    if cat_key not in category_scores:
                        category_scores[cat_key] = rule["weight"]
                        detected_indicators.append({
                            "category": cat_key,
                            "title": rule["title"],
                            "weight": rule["weight"],
                            "explanation": rule["explanation"]
                        })
                    break  # Avoid double counting same rule category

        # 2. URL Specific Analysis
        url_score, url_indicators = self.analyze_urls(message)
        detected_indicators.extend(url_indicators)

        # 3. Calculate Total Weighted Score
        total_score = sum(category_scores.values()) + url_score
        
        # Apply non-linear normalization / capping at 100
        final_score = min(total_score, 100)

        # 4. Determine Risk Level
        if final_score >= 75:
            risk_level = "Critical"
        elif final_score >= 50:
            risk_level = "High"
        elif final_score >= 25:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        # 5. Generate Tailored Recommendations
        recommendations = self.generate_recommendations(risk_level, detected_indicators)

        return {
            "score": final_score,
            "level": risk_level,
            "indicators": detected_indicators,
            "recommendations": recommendations
        }

    def generate_recommendations(self, risk_level, indicators):
        recs = []
        
        if risk_level in ["Critical", "High"]:
            recs.append("DO NOT click any links or download attachments from this message.")
            recs.append("DO NOT reply, share OTPs, passwords, or personal details.")
            recs.append("Verify the sender's identity through official channels (e.g., official website or app).")
            recs.append("Block the sender and report the message as spam/phishing.")
        elif risk_level == "Medium":
            recs.append("Exercise caution. Inspect sender email address or phone number carefully.")
            recs.append("Avoid clicking direct links; navigate manually to the official platform.")
            recs.append("Double check if you expected this communication.")
        else:
            recs.append("No immediate scam indicators detected.")
            recs.append("Always remain vigilant with unsolicited messages containing links or requests for information.")

        return recs
