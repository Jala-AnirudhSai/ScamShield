const sampleMessages = {
    bank: "URGENT SECURITY ALERT: Your Bank of America account has been temporarily locked due to unauthorized login attempts. Click http://192.168.1.1/verify-account immediately or share your OTP code to restore access within 24 hours.",
    lottery: "CONGRATULATIONS! You have been randomly selected as a $1,000,000 lottery winner in our annual lucky draw. Claim your prize right now by visiting http://bit.ly/claim-prize-today before it expires!",
    otp: "Your Netflix login OTP code is 849201. Please reply with your password and OTP code to verify your billing information immediately to prevent service disruption.",
    safe: "Hi Sarah, just checking in to see if we are still meeting for coffee today at 3 PM at Starbucks? Let me know if that time works for you!"
};

function loadSample(type) {
    const textarea = document.getElementById('message');
    if (textarea && sampleMessages[type]) {
        textarea.value = sampleMessages[type];
    }
}

function clearInput() {
    const textarea = document.getElementById('message');
    if (textarea) {
        textarea.value = '';
        textarea.focus();
    }
}

function copyReport() {
    const preview = document.querySelector('.message-preview-box');
    if (preview) {
        navigator.clipboard.writeText(preview.innerText).then(() => {
            alert('Analysis summary copied to clipboard!');
        }).catch(err => {
            console.error('Copy failed: ', err);
        });
    }
}
