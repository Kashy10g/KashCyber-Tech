# CypherCore Setup Guide

## Quick Start (5 minutes)

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 2: Configure Environment
```bash
cp .env.example .env
```

Edit `.env` with your Meta WhatsApp credentials:
```env
WHATSAPP_TOKEN=your_token_from_meta_dashboard
PHONE_NUMBER_ID=your_phone_id_from_meta_dashboard
VERIFY_TOKEN=your_random_string_123
APP_SECRET=your_app_secret_from_meta_dashboard
```

### Step 3: Start the Server
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Step 4: Verify It's Running
```bash
curl http://localhost:8000/
# Should return: {"status": "operational", ...}
```

---

## Meta Dashboard Setup

### 1. Get Your Credentials

**WHATSAPP_TOKEN**:
1. Go to Meta Business Platform → Your Business
2. Navigate to Apps → Your App
3. Go to Settings → Basic
4. Copy **App ID** and **App Secret**
5. Create a **System User** with **Admin** role
6. Generate a long-lived **User Access Token**
7. This becomes your `WHATSAPP_TOKEN`

**PHONE_NUMBER_ID**:
1. Go to WhatsApp → API Setup
2. Find your **Phone Number ID** (looks like: 1234567890123456)
3. Copy and paste into `.env`

**APP_SECRET**:
1. In Meta Dashboard → Settings → Basic
2. Scroll to "App Secret"
3. Click "Show" (requires confirmation)
4. Copy the value

**VERIFY_TOKEN**:
1. Generate any random string (e.g., using: `openssl rand -hex 32`)
2. This is just for your security, not from Meta

---

## Webhook Configuration

### 1. Set Webhook URL in Meta Dashboard
1. Go to WhatsApp → Configuration
2. Under "Webhooks", click "Edit"
3. Set **Callback URL** to: `https://yourdomain.com/webhook`
4. Set **Verify Token** to your `VERIFY_TOKEN` from `.env`
5. Click "Verify and Save"

Meta will send a GET request to your webhook with:
```
GET /webhook?hub.mode=subscribe&hub.verify_token=YOUR_TOKEN&hub.challenge=xxxxx
```

CypherCore automatically handles this.

### 2. Subscribe to Events
1. After webhook is verified, go to "Webhook fields"
2. Enable the following events:
   - ✅ `messages` (to receive incoming messages)
   - ✅ `message_status` (to track delivery)
   - ✅ `message_template_status_update`
3. Click "Save"

---

## Testing

### Test 1: Verify Server is Running
```bash
curl http://localhost:8000/
# Response: {"status": "operational", ...}
```

### Test 2: Check Health
```bash
curl http://localhost:8000/health
# Response: {"status": "healthy", "components": {...}}
```

### Test 3: Send a Test Message
1. Open WhatsApp on your phone
2. Send a message to your bot's phone number
3. You should receive an echo response
4. Check `logs/cyphercore_system.log` for details

### Test 4: Check Logs
```bash
tail -f logs/cyphercore_system.log
```

You should see entries like:
```
2026-04-29 12:34:56 | INFO | CypherCore | meta_verification | WEBHOOK_VERIFIED_SUCCESSFULLY
2026-04-29 12:34:57 | INFO | CypherCore.Processor | handle_event | MESSAGE_EXTRACTED
```

---

## Production Deployment

### Prerequisites
- Linux server or cloud instance (AWS, Google Cloud, Azure, etc.)
- Domain name with HTTPS support
- Python 3.9+
- Supervisor or systemd for process management

### 1. Clone Repository
```bash
git clone https://github.com/yourusername/cyphercore.git
cd cyphercore
```

### 2. Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment
```bash
nano .env  # or use your editor
# Add production values
```

### 5. Create Systemd Service
```bash
sudo nano /etc/systemd/system/cyphercore.service
```

Add:
```ini
[Unit]
Description=CypherCore WhatsApp Bot
After=network.target

[Service]
Type=notify
User=www-data
WorkingDirectory=/home/user/cyphercore
Environment="PATH=/home/user/cyphercore/venv/bin"
ExecStart=/home/user/cyphercore/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### 6. Enable and Start Service
```bash
sudo systemctl daemon-reload
sudo systemctl enable cyphercore
sudo systemctl start cyphercore
sudo systemctl status cyphercore
```

### 7. Setup Nginx Reverse Proxy
```bash
sudo nano /etc/nginx/sites-available/cyphercore
```

Add:
```nginx
server {
    listen 80;
    server_name yourdomain.com;
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 8. Enable SSL with Let's Encrypt
```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com
```

### 9. Restart Nginx
```bash
sudo systemctl restart nginx
```

### 10. Monitor Logs
```bash
sudo journalctl -u cyphercore -f
tail -f logs/cyphercore_system.log
```

---

## Troubleshooting

### Issue: "Invalid Signature" on Every Request
**Solution**: 
- Verify `APP_SECRET` in `.env` matches Meta dashboard
- Restart the server after changing `.env`
- Check that `APP_SECRET` is not truncated

### Issue: "VERIFY_TOKEN not configured"
**Solution**:
- Add `VERIFY_TOKEN=random_string` to `.env`
- Make sure there are no spaces around the `=`
- Restart the server

### Issue: Webhook Not Connecting
**Solution**:
- Verify your domain is publicly accessible
- Check firewall allows port 80 and 443
- Ensure HTTPS is working: `curl https://yourdomain.com/`
- Check Meta's IP whitelist settings

### Issue: Messages Not Being Received
**Solution**:
- Verify webhook is verified in Meta dashboard
- Check that `messages` event is enabled
- Review logs for errors
- Ensure bot's phone number is correctly configured

---

## File Structure

```
cyphercore/
├── main.py              # FastAPI server (entry point)
├── security.py          # Signature validation
├── processor.py         # Business logic
├── requirements.txt     # Python dependencies
├── .env.example         # Environment template
├── .env                 # Configuration (not in git)
├── logs/                # Log files (auto-created)
│   ├── cyphercore_system.log
│   └── cyphercore_errors.log
├── ARCHITECTURE.md      # Architecture documentation
└── SETUP_GUIDE.md       # This file
```

---

## Next Steps

1. ✅ Setup is complete
2. 🔄 Test with sample messages
3. 📊 Monitor logs in real-time
4. 🚀 Deploy to production
5. 🔐 Implement your business logic in `processor.py`

Happy coding! 🚀
