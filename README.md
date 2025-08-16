ReconX — Cyber-Style WHOIS & DNS Recon Tool

A lightweight, cyber-styled reconnaissance suite for WHOIS & DNS lookups, built with Python + Streamlit.

🚀 Features

🌐 WHOIS Lookup → Get domain registration details.
🔍 DNS Resolver → Fetch A, MX, NS, TXT, and CNAME records.
🖥️ Cyberpunk UI → Smooth, stylish, futuristic interface.
⚡ Fast & Lightweight → Runs locally with no external DB.
📦 Single File Tool → Easy to deploy & extend.
📸 Preview

🛠️ Installation

Clone this repository
git clone https://github.com/<your-username>/ReconX.git
cd ReconX


Create & activate virtual environment (optional but recommended)

python -m venv venv
source venv/bin/activate   # Linux / Mac
venv\Scripts\activate      # Windows
Install dependencies
pip install -r requirements.txt

▶️ Usage

Run the tool with Streamlit:
streamlit run reconx.py
Then open http://localhost:8501 in your browser.

📂 Project Structure
ReconX/
│── reconx.py          # Main tool (WHOIS + DNS Recon)
│── requirements.txt   # Dependencies
│── .gitignore         # Git ignore config
│── README.md          # Documentation

⚡ Tech Stack

Python 3.9+
Streamlit → UI framework
python-whois → WHOIS queries
dnspython → DNS resolver

🌟 Roadmap

 Add Reverse DNS Lookup
 Add Subdomain Scanner
 Add Shodan API Integration
 Export results (CSV/JSON/PDF)

🤝 Contributing

Contributions are welcome!
Fork the repo
Create a feature branch (git checkout -b feature-name)
Commit changes (git commit -m "Add feature")
Push & create a PR

📜 License

This project is licensed under the MIT License.

👤 Authors
Mohamed Aries
Fathima Ashraf

Cybersecurity enthusiast | ReconX Creators
