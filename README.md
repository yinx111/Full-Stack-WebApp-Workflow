# Create-a-simple-image-detection-web-app-on-Ubuntu-within-a-VirtualBox-virtual-machine.
Next, I will share step by step how to built a compact but fully functional web app featuring **user registration, login, image detection, result visualization, and file downloading, covering the entire full-stack workflow**.
## My devices
**Host: Windows 10**<br>
**Virtual: Ubuntu 22.04**<br>
**VirtualBox versio: 7.2.2** 

## Technology stack
**Front：HTML/CSS/JS + JWT**<br>
**Back：FastAPI + SQLite + JWT + Argon2 + SMTP**<br>
**Infra：Caddy reverse proxy + DuckDNS dynamic domain name + Router port forwarding (80/443)**

## 1. Create a virtual machine

<img width="570" height="626" alt="虚拟机设置" src="https://github.com/user-attachments/assets/a71c52f7-cdba-49be-8151-75d26fe47b1e" />

## 2. Install miniconda and create conda virtual environment
```bash
conda create -n webapp python=3.10 -y
conda activate webapp
pip install -r requirements.txt
```

## 3. Apply for a free domain name from DuckDNS
Create a folder named **webapp** in your home directory as work folder
```bash
sudo mkdir -p webapp
```

Then go to https://www.duckdns.org/ apply for a free domain name, and remember the **domain name** and **token**.
Create a folder named **duckdns** in work folder, and then create a file named **update.sh** inside it.
```bash
sudo mkdir -p ~/webapp/duckdns
sudo nano ~/webapp/duckdns/update.sh
```

The content of update.sh
```bash
#!/usr/bin/env bash
SUB="your SUB"
TOKEN="your DuckDNS_Token"
```
Update the IP address of the specified DuckDNS subdomain to the public IP address of the machine.
```bash
curl -s "https://www.duckdns.org/update?domains=${your SUB}&token=${your DuckDNS_Token}&ip="

```
Turn update.sh into a script file that can be run directly.
```bash
sudo chmod +x ~/webapp/duckdns/update.sh
```

Create a systemd scheduled task that updates the public IP address every 5 minutes.
```bash
sudo bash -c 'cat >/etc/systemd/system/duckdns.service <<EOF
[Unit]
Description=DuckDNS updater

[Service]
Type=oneshot
ExecStart=~/webapp/duckdns/update.sh
EOF'
```

```bash
sudo bash -c 'cat >/etc/systemd/system/duckdns.timer <<EOF
[Unit]
Description=Run DuckDNS updater every 5 minutes

[Timer]
OnBootSec=30
OnUnitActiveSec=5min
Unit=duckdns.service

[Install]
WantedBy=timers.target
EOF'
```

Reload the systemd configuration, enable and immediately start the DuckDNS scheduled task.
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now duckdns.timer
```
Check if the DuckDNS scheduled task is running.
```bash
sudo systemctl status duckdns.timer --no-pager
```

## 4. Router Port Forwarding
Log in to your router and add 2 ports.

<img width="548" height="91" alt="路由器端口" src="https://github.com/user-attachments/assets/fb142c7d-7380-4f7f-8f34-d46e6a17818d" />

Replace **192.168.11.8** to your virtual machine's local network IP.

## 5. Install Caddy
Install Caddy
```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl

curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
  | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg

curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
  | sudo tee /etc/apt/sources.list.d/caddy-stable.list

sudo chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg
sudo chmod o+r /etc/apt/sources.list.d/caddy-stable.list

sudo apt update
sudo apt install -y caddy
```

Firewall allows access to ports 80 and 443.
```bash
sudo ufw allow 80,443/tcp
```

Use nano to edit Caddy's site configuration and redirect your domain to Uvicorn/FastAPI (:8000) on your local machine as a reverse proxy.
```bash
sudo nano /etc/caddy/Caddyfile
```

The content of Caddyfile
```bash
your SUB.duckdns.org {
    encode gzip
    reverse_proxy 127.0.0.1:8000
}
```

Reload Caddy
```bash
sudo systemctl reload caddy
```

## 6. Email verification
You need to prepare two email addresses: one for sending emails and the other for registering and logging into the service.

Turn on **2-Step Verification** in your Google account and obtain a 16-digit pass using your **App passwords**.

<img width="791" height="483" alt="google2" src="https://github.com/user-attachments/assets/f64d4ce0-0609-46fa-a311-0f9a27771a09" />

<img width="783" height="431" alt="google4" src="https://github.com/user-attachments/assets/8edc0031-c937-4efb-b6f7-c387f88c3519" />

## 7. Install yolo
```bash
conda create -n yolo python=3.10 -y
conda activate yolo
pip install ultralytics
```

## 8. Create detect.sh to set the detection parameters
```bash
#!/usr/bin/env bash
set -e

# Parameters: input image and output image 
IN_PATH="$1"
OUT_PATH="$2"

# Activate conda environment 
source ~/miniconda3/etc/profile.d/conda.sh
conda activate yolo

# Unified detection result directory
RESULT_ROOT="$HOME/result"
mkdir -p "$RESULT_ROOT"

# Result subdir for YOLO outputs
RESULT_DIR="$RESULT_ROOT/yolo_out"

# Clear old results before each detection
rm -rf "$RESULT_DIR"

# Use CPU
export CUDA_VISIBLE_DEVICES=""
# Avoid X display dependency
export MPLBACKEND=Agg

# YOLO model 
MODEL_NAME="${YOLO_MODEL_NAME:-yolo11n.pt}"

# Run YOLO 
yolo predict \
  model="$MODEL_NAME" \
  source="$IN_PATH" \
  save=True \
  project="$RESULT_ROOT" \
  name="yolo_out" \
  exist_ok=True

RESULT_FILE="$(find "$RESULT_DIR" -maxdepth 1 -type f \( -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' \) | head -n 1)"

# Copy to the backend-specified OUT_PATH
cp "$RESULT_FILE" "$OUT_PATH"

```

## 9. Create environment variable file webapp.env
The purpose is to centrally manage critical configurations.
```bash
touch ~/webapp/webapp.env
```
The content of webapp.env
```bash
PUBLIC_BASE_URL=https://your SUB.duckdns.org
DETECT_SH=~/webapp/detect.sh
DETECT_TIMEOUT=120
ACCESS_TOKEN_EXPIRE_MINUTES=60

MAIL_FROM="WebApp <your email ad>"
MAIL_SUBJECT_PREFIX="[WebApp] "
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your email ad
SMTP_PASS=16-digits pass
SMTP_TLS=1
SMTP_SSL=0
```

## 10. Create a one-click launch script
```bash
cd ~/webapp
nano run.sh
```
The content of run.sh
```bash
# Activate conda
source ~/miniconda3/etc/profile.d/conda.sh
conda activate webapp
# Loading your previously set user-level environment variables
set -a
source ~/.webapp.env
set +a
# Start service
exec uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```

Granting executable permissions
```bash
chmod +x run.sh
```

## 11. Run services
```bash
cd webapp
conda activate webapp
./run.sh
```
Then your service will be accessible from the external network.

If you want to access your service on Windows, edit the **hosts** file under path

```bash
C:\Windows\System32\drivers\etc\
```
add  

```bash
Virtual machine IP   your SUB.duckdns.org
```
and save it.























