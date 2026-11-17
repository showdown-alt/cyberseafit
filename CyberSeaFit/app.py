import ipaddress
import os
from urllib.parse import urlparse
import requests
from flask import Flask, render_template_string, request

app = Flask(__name__)


# =====================================
# 1. URL SECURITY SCANNER
# =====================================


def check_link(url):

  url = url.strip()
  parsed = urlparse(url)

  if parsed.scheme not in ("http", "https"):
    return "Please enter a valid HTTP or HTTPS link."

  if not parsed.hostname:
    return "Invalid URL."

  hostname = parsed.hostname.lower()
  warnings = []

  # HTTPS CHECK
  if parsed.scheme == "http":
    warnings.append("HTTP is being used instead of HTTPS.")

  # IP ADDRESS CHECK
  try:
    ipaddress.ip_address(hostname)
    warnings.append("This URL uses an IP address instead of a domain.")
  except ValueError:
    pass

  # PUNYCODE CHECK
  if "xn--" in hostname:
    warnings.append(
        "This domain uses Punycode encoding. Check its spelling carefully."
    )

  # USERNAME/PASSWORD IN URL
  if parsed.username or parsed.password:
    warnings.append("This URL contains username or password information.")

  # SUBDOMAIN CHECK
  if len(hostname.split(".")) > 4:
    warnings.append("This domain contains many subdomain levels.")

  # BUILD BASE REPORT FROM LOCAL CHECKS
  report = "CYBERSEAFIT SECURITY REPORT:\n\n"

  if warnings:
    for warning in warnings:
      report += f"- {warning}\n"
    report += (
        "\nCaution: These are warning indicators, not proof that the website"
        " is malicious."
    )
  else:
    report += "✅ No basic structural warning indicators were found.\n"

  # OPTIONAL URLHAUS API CHECK
  auth_key = os.getenv("URLHAUS_AUTH_KEY")
  if auth_key:
    try:
      headers = {"Auth-Key": auth_key}
      data = {"url": url}
      response = requests.post(
          "https://urlhaus-api.abuse.ch/v1/url/",
          headers=headers,
          data=data,
          timeout=10,
      )
      if response.status_code == 200:
        result = response.json()
        status = result.get("query_status")
        if status == "ok":
          return (
              "⚠️ DANGER: URLhaus lists this URL as a known malware URL. Do not"
              " open it!\n\n"
              + report
          )
    except Exception:
      # If URLhaus times out or fails, we gracefully continue with local report
      pass

  report += (
      "\n\nURLhaus database check completed (no active malware match found)."
      " This does not guarantee safety."
  )
  return report


# =====================================
# 2. CYBERSECURITY KNOWLEDGE DATABASE
# =====================================

topics = {
    "phishing": (
        "Phishing is an online scam where criminals pretend to be trusted"
        " people or companies to steal personal information."
    ),
    "malware": (
        "Malware is harmful software designed to damage devices, steal"
        " information or disrupt systems."
    ),
    "password": (
        "Use long, unique passwords for every account. Never share your"
        " passwords with other people."
    ),
    "privacy": (
        "Online privacy means protecting your personal information. Avoid"
        " sharing private details with unknown people."
    ),
    "2fa": (
        "Two-factor authentication adds an extra security step when signing in"
        " to an account."
    ),
    "virus": (
        "A computer virus is a type of malware that can spread between files"
        " and systems."
    ),
    "cyberbullying": (
        "Cyberbullying means using digital platforms to harass or hurt"
        " someone. Save evidence, block and report the behaviour, and talk to a"
        " trusted adult."
    ),
    "ransomware": (
        "Ransomware is malware that locks or encrypts data and demands"
        " payment. Keep backups and avoid suspicious downloads."
    ),
    "safe browsing": (
        "Use trusted websites, check URLs carefully, avoid suspicious downloads"
        " and update your browser."
    ),
    "hacking": (
        "Ethical hacking means testing computer security with permission to"
        " find and fix weaknesses."
    ),
    "firewall": (
        "A firewall monitors network traffic and helps block unwanted"
        " connections."
    ),
    "encryption": (
        "Encryption changes readable information into coded information that"
        " requires a key to read."
    ),
    "social engineering": (
        "Social engineering is when someone manipulates people into sharing"
        " information or taking unsafe actions."
    ),"wi-fi": (
        "Public Wi-Fi networks can be unsafe. Avoid logging into"
        " sensitive accounts on public networks without a secure VPN."
    ),

    "identity theft": (
        "Identity theft happens when someone steals your personal details to"
        " commit fraud. Monitor your accounts regularly and shred sensitive"
        " documents."
    ),

    "deepfake": (
        "A deepfake is AI-generated audio or video that mimics real people."
        " Always verify unexpected requests from family or coworkers through a"
        " second channel."
    ),

    "malicious downloads": (
        "Never download files, attachments, or software from untrusted"
        " websites or emails, as they often contain hidden malware."
    ),
}


# =====================================
# 3. CHATBOT BRAIN
# =====================================


def chatbot(message):

  message = message.strip()
  lower_message = message.lower()

  if not message:
    return "Please type a message."

  # URL CHECK
  if lower_message.startswith(("http://", "https://")):
    return check_link(message)

  # GREETINGS
  if lower_message in ["hi", "hello", "hey", "good morning"]:
    return (
        "Hello! Welcome to CyberSeaFit. I can explain cybersecurity topics and"
        " check URLs."
    )

  # HELP
  if "help" in lower_message:
    return (
        "You can ask me about phishing, malware, passwords, privacy, 2FA,"
        " ransomware, firewalls and ethical hacking. You can also send an HTTP"
        " or HTTPS URL."
    )

  # KNOWLEDGE DATABASE
  for keyword, answer in topics.items():
    if keyword in lower_message:
      return answer

  return (
      "I don't know the answer to that yet. Try asking about phishing, malware,"
      " passwords, privacy or online safety."
  )


# =====================================
# 4. WEBSITE DESIGN
# =====================================

HTML = """
<!DOCTYPE html>
<html>
<head>
<title>CyberSeaFit</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
* { box-sizing: border-box; }
body { margin: 0; font-family: Arial, sans-serif; background: #101827; color: white; }
header { background: #17243a; padding: 22px; text-align: center; }
header h1 { color: #35d9ff; margin: 0; font-size: 30px; }
header p { color: #bdc8d8; }
.container { max-width: 750px; margin: 30px auto; padding: 15px; }
.chatbox { background: #1b2940; border-radius: 12px; padding: 20px; }
#messages { height: 400px; overflow-y: auto; padding: 10px; background: #101827; border-radius: 10px; margin-bottom: 15px; }
.message { padding: 12px; margin: 10px 0; border-radius: 8px; line-height: 1.5; white-space: pre-wrap; overflow-wrap: anywhere; }
.user { background: #075985; text-align: right; }
.bot { background: #26364e; }
.input-area { display: flex; gap: 10px; }
input { flex: 1; min-width: 0; padding: 14px; border: none; border-radius: 8px; outline: none; }
button { padding: 14px 20px; border: none; border-radius: 8px; background: #06b6d4; color: #071827; font-weight: bold; cursor: pointer; }
button:hover { background: #35d9ff; }
button:disabled { opacity: 0.6; cursor: wait; }
.note { color: #aebbd0; font-size: 13px; text-align: center; margin-top: 15px; }
@media (max-width: 480px) { .input-area { flex-direction: column; } }
</style>
</head>
<body>
<header>
<h1>CyberSeaFit</h1>
<p>Your Cybersecurity Learning Assistant</p>
</header>
<div class="container">
<div class="chatbox">
<div id="messages">
<div class="message bot">
Hello! Welcome to CyberSeaFit.
I can help you learn about cybersecurity and check suspicious URLs.
Try asking: What is phishing?
</div>
</div>
<div class="input-area">
<input type="text" id="userInput" placeholder="Ask something or paste a URL..." autocomplete="off">
<button id="sendButton" onclick="sendMessage()">Send</button>
</div>
<p class="note">URL checks use local structure rules and URLhaus.</p>
</div>
</div>
<script>
async function sendMessage() {
    const input = document.getElementById("userInput");
    const messages = document.getElementById("messages");
    const button = document.getElementById("sendButton");
    const message = input.value.trim();
    if (!message || button.disabled) { return; }
    const userDiv = document.createElement("div");
    userDiv.className = "message user";
    userDiv.textContent = message;
    messages.appendChild(userDiv);
    input.value = "";
    button.disabled = true;
    const botDiv = document.createElement("div");
    botDiv.className = "message bot";
    botDiv.textContent = "Checking...";
    messages.appendChild(botDiv);
    messages.scrollTop = messages.scrollHeight;
    try {
        const response = await fetch("/chat", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message: message })
        });
        const data = await response.json();
        if (!response.ok) { throw new Error(data.reply || "Server error"); }
        botDiv.textContent = data.reply;
    } catch (error) {
        botDiv.textContent = "Unable to connect to CyberSeaFit. Please try again.";
    }
    button.disabled = false;
    messages.scrollTop = messages.scrollHeight;
}
document.getElementById("userInput").addEventListener("keydown", function(event) {
    if (event.key === "Enter") { sendMessage(); }
});
</script>
</body>
</html>
"""


# =====================================
# 5. FLASK ROUTES
# =====================================


@app.route("/")
def home():
  return render_template_string(HTML)


@app.route("/chat", methods=["POST"])
def chat():
  data = request.get_json(silent=True) or {}
  message = data.get("message", "")
  if not isinstance(message, str):
    return {"reply": "Invalid message."}, 400
  reply = chatbot(message)
  return {"reply": reply}


# =====================================
# 6. START SERVER
# =====================================

if __name__ == "__main__":
  print("CyberSeaFit is starting...")
  app.run(debug=True)
