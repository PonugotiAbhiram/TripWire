# TripWire - Honeypot Sensor (Step 1, Step 2 & Step 3)

TripWire is a lightweight honeypot built for a Computer Networks college project.
- **STEP 1**: Implements a **fake web honeypot** (Port 8080) mimicking Router & WordPress login panels, and a private local Admin API (Port 3000).
- **STEP 2**: Implements a **demo attacker script** (`scripts/demo-attacker.js`) to generate controlled, repeatable test traffic against your honeypot.
- **STEP 3**: Implements **fake TCP doors** for **Telnet** (Port 2323), **FTP** (Port 2121), and **SSH** (Port 2222) using Node.js `net` sockets, capturing connection sweeps, credentials, and client tool banners.

---

## 📁 Project Structure

```text
tripwire/
├── scripts/
│   ├── demo-attacker.js # Demo traffic generator (port sweep, bruteforce, web probes, telnet)
│   └── test-doors.js    # Automated door test suite (cap, counter, reset, IAC, silent connect, idle)
├── sensor/
│   ├── db.js          # Database connection, SQLite WAL mode setup, tables & indexes
│   ├── reporter.js    # Central log processor (sanitizes & caps inputs, executes SQL inserts)
│   ├── fakeWeb.js     # Fake web door routes (port 8080), middleware, & error handlers
│   ├── fakeTelnet.js  # Fake Telnet door (port 2323) with prompt loop & IAC stripping
│   ├── fakeFtp.js     # Fake FTP door (port 2121) handling USER, PASS, QUIT & raw commands
│   ├── fakeSsh.js     # Fake SSH door (port 2222) capturing client SSH version string
│   ├── adminApi.js    # Private local REST API (port 3000 bound to 127.0.0.1)
│   └── index.js       # Main entry point starting DB and all honeypot doors
├── package.json       # Node.js project manifest and dependencies
└── README.md          # Project documentation and test guide
```

---

## ⚙️ Requirements & Installation

1. **Node.js** (v16+ recommended)
2. Open terminal in the `tripwire` project root folder:
   ```bash
   npm install
   ```

---

## 🚀 How to Run Honeypot Sensor

Start the honeypot sensor:
```bash
npm start
```
You will see console startup logs confirming:
- **Fake Web Doors**: Listening on `http://127.0.0.1:8080`
- **Admin API**: Listening on `http://127.0.0.1:3000/api/events`
- **Fake Telnet**: Listening on `127.0.0.1:2323`
- **Fake FTP**: Listening on `127.0.0.1:2121`
- **Fake SSH**: Listening on `127.0.0.1:2222`

---

## 🧪 Running the Automated Test Suite (`test-doors.js`)

With `npm start` running in one terminal, run the door test suite in a second terminal:

```bash
# Run all door verification tests (including ~30s idle timeout test f)
node scripts/test-doors.js

# Fast mode (skips test f idle timeout test)
node scripts/test-doors.js --skip-slow
```

### Test Suite Checks Covered:
- **Test a (Cap test)**: Sends 25 simultaneous connections to port 2323; verifies at most 20 stay open.
- **Test b (Counter test)**: After closing cap sockets, verifies a new connection receives the login prompt.
- **Test c (Reset test)**: Destroys a socket mid-line without newline; verifies the door remains operational.
- **Test d (IAC test)**: Sends Telnet IAC byte sequence (`0xFF 0xFD 0x01`) before `admin\r\n`; verifies captured username in `/api/events` is exactly `"admin"` (length 5).
- **Test e (Silent SSH Connect)**: Connects to SSH port 2222 without sending data; verifies a `CONNECT` event with `protocol: 'ssh'` is logged.
- **Test f (Idle Timeout test)**: Connects to FTP port 2121 and waits; verifies the connection is closed after ~30s idle timeout.

---

## ⚔️ STEP 2 & 3: Running the Demo Attacker Script

In a second terminal window (while the honeypot sensor is running), execute the demo attacker script:

```bash
node scripts/demo-attacker.js
```

### CLI Options

| Flag | Description | Default | Example |
| --- | --- | --- | --- |
| `--target <ip>` | Target IP or localhost (Must be localhost or private range `127.x`, `10.x`, `192.168.x`, `172.16-31.x`, `::1`) | `127.0.0.1` | `node scripts/demo-attacker.js --target 127.0.0.1` |
| `--delay <ms>` | Inter-request delay in milliseconds | `200` | `node scripts/demo-attacker.js --delay 100` |
| `--phase <1\|2\|3>` | Run a specific phase only (`1`: Port Sweep, `2`: Passwords, `3`: Web Paths) | All phases | `node scripts/demo-attacker.js --phase 2` |

---

## 🧪 Testing Fake TCP Doors Manually

### 1. Testing Fake Telnet (Port 2323)

#### Using Standard `telnet` or `nc` (Linux / macOS / WSL)
```bash
telnet 127.0.0.1 2323
# Enter username when prompted: admin
# Enter password when prompted: admin123
```

#### Using Windows PowerShell (`TcpClient` Alternative)
```powershell
$client = New-Object System.Net.Sockets.TcpClient("127.0.0.1", 2323)
$stream = $client.GetStream()
$reader = New-Object System.IO.StreamReader($stream)
$writer = New-Object System.IO.StreamWriter($stream)
$writer.AutoFlush = $true

$reader.ReadLine() # Read banner "Ubuntu 20.04 LTS"
$writer.WriteLine("admin")
$reader.ReadLine() # Read "Password:"
$writer.WriteLine("SuperSecretPass")
$reader.ReadLine() # Read "Login incorrect"
$client.Close()
```

---

### 2. Testing Fake FTP (Port 2121)

#### Using Standard `ftp` or `nc` (Linux / macOS / WSL)
```bash
ftp 127.0.0.1 2121
# User: admin
# Password: wrongpassword
```

#### Using Windows PowerShell (`TcpClient` Alternative)
```powershell
$client = New-Object System.Net.Sockets.TcpClient("127.0.0.1", 2121)
$stream = $client.GetStream()
$reader = New-Object System.IO.StreamReader($stream)
$writer = New-Object System.IO.StreamWriter($stream)
$writer.AutoFlush = $true

$reader.ReadLine() # Read "220 FTP server ready"
$writer.WriteLine("USER root")
$reader.ReadLine() # Read "331 Password required"
$writer.WriteLine("PASS 123456")
$reader.ReadLine() # Read "530 Login incorrect"
$writer.WriteLine("QUIT")
$client.Close()
```

---

### 3. Testing Fake SSH (Port 2222)

#### Using Standard `ssh` or `nc` (Linux / macOS / WSL)
```bash
ssh -p 2222 root@127.0.0.1
```

#### Using Windows PowerShell (`TcpClient` Alternative)
```powershell
$client = New-Object System.Net.Sockets.TcpClient("127.0.0.1", 2222)
$stream = $client.GetStream()
$reader = New-Object System.IO.StreamReader($stream)
$writer = New-Object System.IO.StreamWriter($stream)
$writer.AutoFlush = $true

$reader.ReadLine() # Read SSH server banner
$writer.WriteLine("SSH-2.0-TestAttackerClient_1.0")
$client.Close()
```

---

## 📊 Admin API Endpoints (Port 3000 - Local Only)

Administrative REST API endpoints are bound strictly to `127.0.0.1:3000`:

### 1. `GET /api/events`
Returns the 100 most recent logged events, newest first.
```bash
curl http://127.0.0.1:3000/api/events
```

### 2. `GET /api/attackers`
Returns the 100 most recent attacker IP addresses with threat level assessments, sorted by severity score descending.
```bash
curl http://127.0.0.1:3000/api/attackers
```

### 3. `GET /api/attackers/:ip`
Returns detailed profile metrics, threat assessment, and chronological activity timeline for a specific IP.
```bash
curl http://127.0.0.1:3000/api/attackers/127.0.0.1
```

### 4. `GET /api/stats`
Returns system-wide metrics including total event count, unique IP count, top passwords/usernames, events per protocol, events per hour (last 24h), and threat level distribution.
```bash
curl http://127.0.0.1:3000/api/stats
```

---

## 🛡️ Security Features Implemented

1. **No Code Execution**: All payload inputs and SSH version banners are treated strictly as plain text strings.
2. **SQL Injection Safeguard**: All queries use parameterized statements.
3. **DoS Safeguards**:
   - Web request bodies capped at `10KB`.
   - TCP doors capped at **max 20 concurrent connections** (extra connections dropped immediately).
   - TCP sockets time out after **30s idle**.
   - Input lines capped at **256 bytes**, max **20 lines** per connection.
4. **CONNECT & DISCONNECT Logging**: Logs `CONNECT` on socket open and `DISCONNECT` on socket close across all TCP doors.
5. **Real IP Extraction**: Uses `socket.remoteAddress` and strips `::ffff:`.
6. **Local-Only Admin API**: Binds port `3000` strictly to `127.0.0.1` with `X-Content-Type-Options: nosniff` and `Cache-Control: no-store` headers on `/api` routes.

