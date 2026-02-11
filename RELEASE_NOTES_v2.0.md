# VulnShop v2.0 - Release Notes

## New Features Added

### 🆕 Container Exploitation Lab
**Files Added:**
- `templates/container_info.html` - Container environment detection
- `templates/container_escape.html` - Interactive escape technique demos

**Routes Added:**
- `/container-info` - Detect Docker, check capabilities, enumerate environment
- `/container-escape` - Demonstrate escape techniques (Docker socket, cgroup, proc)

**Skills Covered:**
- Docker environment detection
- Capability enumeration (CAP_SYS_ADMIN, etc.)
- Docker socket exploitation
- cgroup escape (CVE-2019-5736 style)
- /proc filesystem attacks
- Host access from containers

---

### 🆕 AI Attack Lab (10 Techniques)
**Files Added:**
- `templates/ai_lab.html` - Main dashboard with all 10 attack types
- `templates/ai_prompt_injection.html` - LLM prompt manipulation
- `templates/ai_data_poisoning.html` - ML dataset corruption
- `templates/ai_adversarial.html` - FGSM adversarial examples
- `templates/ai_model_inversion.html` - Training data reconstruction
- `templates/ai_model_stealing.html` - Model extraction via API

**Routes Added:**
- `/ai-lab` - Main AI lab dashboard
- `/ai-lab/prompt-injection` - Prompt injection attack demo (GET/POST)
- `/ai-lab/data-poisoning` - Data poisoning attack demo (POST)
- `/ai-lab/adversarial` - Adversarial attack demo (POST)
- `/ai-lab/model-inversion` - Model inversion demo (POST)
- `/ai-lab/model-stealing` - Model stealing demo (POST)

**Attack Techniques Covered:**
1. **Prompt Injection** - Manipulate LLMs to bypass safety controls
2. **Data Poisoning** - Corrupt training datasets
3. **Adversarial Attacks** - FGSM image classifier fooling
4. **Model Inversion** - Reconstruct private training data
5. **Backdoor Attacks** - Hidden triggers (demo only)
6. **Model Stealing** - Clone proprietary models via API
7. **Bias Amplification** - Exploit overfitting (demo only)
8. **Resource Exhaustion** - AI DoS attacks (demo only)
9. **Supply Chain** - Compromise AI dependencies (demo only)
10. **Human-AI Exploits** - Social engineering (demo only)

---

## Updated Files

### `app.py`
- Added 7 new routes for container and AI labs
- Implemented interactive demos with simulated AI responses
- Added container detection logic
- Fixed escape sequence warning (line 486)

### `templates/base.html`
- Added "Container" dropdown menu with 2 options
- Added "AI Attack" dropdown menu with 6 options
- Updated navigation structure

### `README.md`
- Added **Phase 4: Advanced Exploitation** to syllabus coverage
- Added vulnerability sections 9 & 10 (Container + AI)
- Added **Scenario 3: Container Escape Attack**
- Added **Scenario 4: AI Model Exploitation** (5 sub-scenarios)
- Updated key features and overview
- Added learning resources for container and AI security

---

## Technical Details

### Backend Logic

#### Prompt Injection Demo
- Simulates vulnerable LLM with system prompt containing secret
- Detects injection keywords: "ignore", "disregard", "admin password"
- Returns leaked secrets when injection succeeds

#### Data Poisoning Demo
- Simulated spam classifier starting at 85% accuracy
- Tracks poisoned samples that flip labels
- Drops accuracy progressively as dataset is corrupted

#### Adversarial Attack Demo
- Simulates FGSM on image classifier
- Shows original prediction vs adversarial prediction
- Demonstrates imperceptible perturbations causing misclassification

#### Model Inversion Demo
- Simulates iterative reconstruction attack
- Shows progress bar for gradient-based inversion
- Returns reconstructed facial features with accuracy metrics

#### Model Stealing Demo
- Simulates API query-based model extraction
- Supports 3 strategies: random, active learning, adaptive
- Returns model fidelity and performance comparison

---

## Testing Checklist

✅ **Container Lab:**
- [ ] Navigate to /container-info
- [ ] Check Docker environment detection
- [ ] View capabilities and cgroup info
- [ ] Test /container-escape interface
- [ ] Try all 3 escape techniques

✅ **AI Lab:**
- [ ] Navigate to /ai-lab
- [ ] Test prompt injection (extract API key)
- [ ] Test data poisoning (drop accuracy below 60%)
- [ ] Test adversarial attack (flip prediction)
- [ ] Test model inversion (reconstruct image)
- [ ] Test model stealing (clone model with 90%+ fidelity)

✅ **Navigation:**
- [ ] Container dropdown appears when logged in
- [ ] AI Attack dropdown appears when logged in
- [ ] All links work correctly

---

## References

- **Container Security:**
  - CVE-2019-5736: runc container escape
  - Docker socket privilege escalation techniques

- **AI Security:**
  - Article: [AI Mind Attack - 10 Teknik Penyerang Exploitasi AI](https://medium.com/@mansheman/ai-mind-attack-10-teknik-penyerang-exploitasi-ai-aed003df1952)
  - OWASP Top 10 for LLM Applications
  - Adversarial Robustness Toolbox (ART)
  - Papers: Goodfellow et al. (FGSM), Tramèr et al. (Model Stealing)

---

## Deployment

### Native Deployment
```bash
cd /home/h3llo/Documents/0x-lab/xlab/ManBehindtheHat
source venv/bin/activate
python app.py
```

### Docker Deployment
```bash
docker-compose up -d
# Container labs will work properly in Docker environment
```

### Testing Container Features
For full container exploitation features, deploy in Docker:
```bash
docker run -it --privileged -v /var/run/docker.sock:/var/run/docker.sock vulnshop
```

---

## Security Warnings

⚠️ **NEVER deploy this in production!**

This application is intentionally vulnerable and includes:
- No input validation
- No authentication checks on critical endpoints
- Exposed secrets and keys
- Command injection vulnerabilities
- File upload RCE
- Container escape demonstrations
- AI attack simulations

**Use only in isolated lab environments!**

---

## Version History

- **v1.0** - Initial release with 8 vulnerability types
- **v2.0** - Added Container Exploitation Lab + AI Attack Lab (15+ vulnerabilities)

---

## Credits

Developed for: **Offensive Security Bootcamp**
Educational Purpose: Web application penetration testing training

Built with:
- Flask 2.3.0
- Python 3.8+
- Bootstrap 5.3
- SQLite3

---

## What's Next?

Future enhancements could include:
- Kubernetes escape scenarios
- More AI attack types (model backdoors, membership inference)
- GraphQL injection vulnerabilities
- WebSocket exploitation
- OAuth/JWT vulnerabilities
- API security testing scenarios

---

**Happy Learning! 🎓**
