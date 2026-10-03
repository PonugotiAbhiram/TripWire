# TripWire - Honeypot Sensor (Step 1)

TripWire is a lightweight honeypot built for a Computer Networks college project. STEP 1 implements a **fake web honeypot** that mimics vulnerable web login forms (Router Management & WordPress login) and logs all incoming attack traffic into a local SQLite database.

---

## 📁 Project Structure

```text
tripwire/
├── sensor/
│   ├── db.js          # Database connection, SQLite WAL mode setup, tables & indexes
│   ├── reporter.js    # Central log processor (sanitizes & caps inputs, executes SQL inserts)
│   ├── fakeWeb.js     # Fake web door routes (port 8080), middleware, & error handlers
│   ├── adminApi.js    # Private local REST API (port 3000 bound to 127.0.0.1)
│   └── index.js       # Main entry point starting DB and both servers
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

## 🚀 How to Run

Start the honeypot sensor:
```bash
npm start
```
You will see console startup logs confirming:
- **Fake Web Doors**: Listening on port `8080` (public)
- **Admin API**: Listening on `http://127.0.0.1:3000` (private)

---

## 🧪 Testing with `curl`

Open a second terminal window while `npm start` is running and test the honeypot doors using these `curl` commands:

### 1. Test Router Login Page (GET `/` or `/login`)
```bash
curl -i http://localhost:8080/login
```

### 2. Test Router Login Form Submission (POST `/login`)
```bash
curl -i -X POST -d "username=admin&password=SuperSecretPassword123" http://localhost:8080/login
```

### 3. Test WordPress Login Page (GET `/wp-login.php`)
```bash
curl -i http://localhost:8080/wp-login.php
```

### 4. Test WordPress Login Form Submission (POST `/wp-login.php`)
```bash
curl -i -X POST -d "log=admin@example.com&pwd=WrongPassword!" http://localhost:8080/wp-login.php
```

### 5. Test Reconnaissance / Scanner 404 Door (GET `/.env`)
```bash
curl -i http://localhost:8080/.env
```

### 6. Test Oversized Payload Protection (413 Payload Too Large)
```bash
curl -i -X POST -H "Content-Type: application/x-www-form-urlencoded" --data-raw "data=$(head -c 12000 /dev/zero | tr '\0' 'a')" http://localhost:8080/login
```

### 7. Fetch Logged Events from Admin API (Port 3000)
```bash
curl http://127.0.0.1:3000/api/events
```

---

## 🛡️ Security Features Implemented

1. **No Code Execution**: Attacker payload inputs are handled purely as plain text strings.
2. **SQL Injection Safeguard**: All queries use parameterized statements via `better-sqlite3`.
3. **DoS Protection**: Request body parser capped at `10KB`.
4. **Input Truncation**: Strings capped at `500` characters, headers capped at `30` keys with `200` characters per header value before saving.
5. **Real IP Extraction**: Uses `req.socket.remoteAddress` and strips `::ffff:`. Ignores untrusted `X-Forwarded-For`.
6. **Server Obfuscation**: Hides `X-Powered-By` response header.
7. **Local-Only Admin API**: Binds port `3000` strictly to `127.0.0.1`.
8. **Fault Tolerance**: Wrapped in `try/catch` logic so database or payload parsing errors will never crash the sensor.
