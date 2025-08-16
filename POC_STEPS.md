#Step 1:
#Clone the Repository

git clone https://github.com/MohamedAries07/ReconX.git
cd ReconX

#Step 2:
#Check Python Installation

python3 --version

#Step 3:
#If Python is not installed, run:

sudo apt update && sudo apt install python3 python3-pip -y

#Step 4:
#Install Dependencies
#From the root folder (where reconx.py is located):

pip install -r requirements.txt

#Step 5:
#If requirements.txt is not available, install manually:

pip install streamlit requests python-whois dnspython

#Step 6:
#Run ReconX

streamlit run reconx.py

#Step 7:
#Open in Browser
#After running, open this link in your browser:
http://localhost:8501

#Notes
#Always run from the root folder where reconx.py exists.
#to be noted
#If pip gives errors, upgrade it:

pip install --upgrade pip


#Works on Linux (Kali/Ubuntu), Windows, and macOS.
