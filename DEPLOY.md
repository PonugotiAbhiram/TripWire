# Deploying TripWire Honeypot to the Cloud

This guide will walk you step-by-step through deploying the TripWire Honeypot to a Linux cloud virtual machine (VM). 

> **Important Policy Note**: Before deploying a honeypot, check your cloud provider's Acceptable Use Policy (AUP). Some providers strictly prohibit running honeypots, malware analysis, or listening on vulnerable ports. Ensure you are permitted to run this type of software.

## Prerequisites
1. A separate Linux VM (Ubuntu/Debian recommended) with **no real data, no actual services, and no important SSH keys**.
2. A non-root user (e.g. `tripwire`).
3. Node.js version 22 or higher installed system-wide. **Do not use `nvm` for this service**, as systemd needs a global path. To install Node 22+ via NodeSource:
   ```bash
   curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
   sudo apt-get install -y nodejs
   ```
   Check that `which node` prints `/usr/bin/node` and `node -v` prints `v22` or higher.
4. **Note for private repositories**: If your repo is private, copy the project using `scp` from your local machine or use a read-only deploy token. **Never put your personal SSH keys on the VM.**

## Step 1: Move Real SSH Port Before Redirects
Because we want to catch attackers connecting to the standard SSH port (22), we need to move the *real* SSH daemon to a different port (e.g., 22222) so it doesn't conflict with our fake door. Do this **before** adding any iptables redirects to avoid locking yourself out.

1. **First**, in your cloud provider's dashboard, configure the firewall to open port `22222/tcp` **strictly only to your own IP address**. Also ensure `21/tcp`, `22/tcp`, `23/tcp`, and `80/tcp` are open to `0.0.0.0/0`. Never open port `3000` to the internet.
2. **Second**, open `/etc/ssh/sshd_config` on the VM. Find the line `#Port 22` (or `Port 22`). **Add `Port 22222` and keep `Port 22`** until the new port is tested, then remove `Port 22` later.
3. **Third**, on newer Ubuntu versions (22.10+/24.04), SSH might use socket-based activation instead of a persistent service. To handle this, either override `ListenStream` or cleanly disable the socket entirely:
   ```bash
   sudo systemctl disable --now ssh.socket
   sudo systemctl enable --now ssh.service
   ```
4. Restart SSH and verify it's listening on the new port:
   ```bash
   sudo systemctl restart ssh
   ss -ltnp | grep sshd
   ```
5. **Fourth**, open a *NEW* terminal window on your local machine and test the connection:
   ```bash
   ssh -p 22222 user@your-vm-ip
   ```
6. **Only when you have successfully logged in via the new window** should you close your original window, edit `/etc/ssh/sshd_config` to remove `Port 22`, restart SSH, and proceed to iptables redirects.

> **Locked out?** If you lose SSH access, use your cloud provider's web or serial console to log in and fix `sshd_config` or your firewall rules. Note that home IPs often change dynamically; if this happens, you will need to update the firewall rule in the cloud provider's console to match your new IP, or explicitly allow a small trusted IP range.

## Step 2: Set up iptables Redirects
The honeypot doors run on unprivileged ports (2121, 2222, 2323, 8080) because non-root users cannot bind to ports below 1024. We use `iptables` to silently redirect traffic from the standard ports to our honeypot ports.

Run these commands as root:
```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 21 -j REDIRECT --to-port 2121
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2323
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
```

To persist these rules across reboots, install `iptables-persistent` and save:
```bash
sudo apt update
sudo apt install iptables-persistent
sudo netfilter-persistent save
```

To verify your redirects are active, check the NAT table:
```bash
sudo iptables -t nat -L PREROUTING -n --line-numbers
```

## Step 3: Clone and Install
Prepare the deployment directory `/opt/tripwire` and set up the code as your non-root user:

```bash
sudo mkdir -p /opt/tripwire
sudo chown tripwire:tripwire /opt/tripwire
# Clone or copy into /opt/tripwire as user tripwire
git clone https://github.com/your-username/tripwire.git /opt/tripwire
cd /opt/tripwire
npm install
```

## Step 4: Configure Environment
Copy the example environment file, set permissions, and set your secure admin password:
```bash
cd /opt/tripwire
cp deploy/env.example .env
chmod 600 .env
nano .env
```
Ensure you have set:
- `ADMIN_PASSWORD=your_secure_long_password` (Must be at least 12 characters)
- `BIND_HOST=0.0.0.0` (This binds *only the fake doors* to all interfaces. The admin dashboard remains strictly bound to `127.0.0.1`).

## Step 5: Set up the Systemd Service
To ensure the honeypot starts on boot and restarts if it crashes:

1. Copy the provided service file to systemd:
   ```bash
   sudo cp /opt/tripwire/deploy/tripwire.service /etc/systemd/system/
   ```
2. Reload systemd, enable, and start the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable tripwire
   sudo systemctl start tripwire
   ```
3. Check the status: `sudo systemctl status tripwire`.

## Step 6: Verification
Verify the ports are listening correctly using `ss`:
```bash
ss -ltnp
```
You should see:
- Port `3000` bound exactly to `127.0.0.1`.
- Ports `2121`, `2222`, `2323`, and `8080` bound to `0.0.0.0` (or `*`).
- Port `22222` bound by `sshd`.

## Step 7: Accessing the Dashboard Securely
Since port 3000 is not exposed to the internet, you must use an SSH tunnel from your local machine to view the dashboard:

```bash
ssh -L 3000:127.0.0.1:3000 tripwire@your-vm-ip -p 22222
```
Now, open your local web browser and go to `http://localhost:3000`. You will be prompted to log in using the `ADMIN_PASSWORD` you set in the `/opt/tripwire/.env` file.
