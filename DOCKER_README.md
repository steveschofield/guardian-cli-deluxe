# Guardian CLI Deluxe - Kali Linux Docker 🐳

**Complete, production-ready Dockerfile for running Guardian CLI Deluxe on Kali Linux**

## 🚀 Quick Start (Fully Automated)

```bash
# 1. Clone the repository
git clone https://github.com/steveschofield/guardian-cli-deluxe.git
cd guardian-cli-deluxe

# 2. Copy these Docker files to your repo root
cp Dockerfile.kali .
cp docker-compose.yml .
cp .dockerignore .
cp docker-build-run.sh .

# 3. Create .env file with your API keys
cat > .env << 'EOF'
ANTHROPIC_API_KEY=your_key_here
GOOGLE_API_KEY=your_key_here
EOF

# 4. Run the automated build script
chmod +x docker-build-run.sh
./docker-build-run.sh

# That's it! Guardian is now running in Docker
```

## 📦 What's Included

### Core Tools
- **Kali Linux Rolling** (latest)
- **Python 3** with pip
- **All Guardian dependencies**
- **150+ penetration testing tools**

### Key Pentesting Tools
- ✅ **Nmap** - Network scanner
- ✅ **Enum4linux / Enum4linux-ng** - SMB enumeration (null session fixed!)
- ✅ **SQLmap** - SQL injection
- ✅ **Nikto** - Web server scanner
- ✅ **Nuclei** - Vulnerability scanner
- ✅ **Metasploit** - Exploitation framework
- ✅ **Hydra** - Brute force
- ✅ **Gobuster / FFuF** - Directory busting
- ✅ **Dalfox** - XSS scanner
- ✅ **Commix** - Command injection
- ✅ **And 140+ more...**

### Python Libraries
- Anthropic (Claude API)
- LangChain
- Google Generative AI
- OpenAI
- Impacket
- Scapy
- Requests
- BeautifulSoup
- And all Guardian requirements

## 🎯 Usage

### Method 1: Using the Automated Script (Recommended)

```bash
# Build and run everything automatically
./docker-build-run.sh

# Or use specific commands:
./docker-build-run.sh build    # Build the image
./docker-build-run.sh run      # Start container
./docker-build-run.sh shell    # Open shell
./docker-build-run.sh stop     # Stop container
./docker-build-run.sh clean    # Clean up everything
./docker-build-run.sh logs     # View logs
./docker-build-run.sh test     # Test installation
./docker-build-run.sh scan <target>  # Run scan
```

### Method 2: Using Docker Compose

```bash
# Build and start
docker compose up -d --build

# Enter the container
docker compose exec guardian-kali bash

# Stop
docker compose down

# View logs
docker compose logs -f

# Rebuild from scratch
docker compose down -v
docker compose up -d --build
```

### Method 3: Manual Docker Commands

```bash
# Build
docker build -t guardian-cli-deluxe:kali-latest -f Dockerfile.kali .

# Run interactively
docker run -it --rm \
  --name guardian-kali \
  -v $(pwd):/guardian \
  -e ANTHROPIC_API_KEY=your_key \
  guardian-cli-deluxe:kali-latest

# Run in background
docker run -d \
  --name guardian-kali \
  -v $(pwd):/guardian \
  -e ANTHROPIC_API_KEY=your_key \
  guardian-cli-deluxe:kali-latest \
  tail -f /dev/null

# Enter shell
docker exec -it guardian-kali bash

# Stop
docker stop guardian-kali && docker rm guardian-kali
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# Required: At least one AI provider
ANTHROPIC_API_KEY=sk-ant-xxxxx
GOOGLE_API_KEY=xxxxx
OPENAI_API_KEY=sk-xxxxx

# Optional: Guardian settings
GUARDIAN_LOG_LEVEL=INFO
GUARDIAN_MAX_WORKERS=4
GUARDIAN_CONFIG=/guardian/config/guardian.yaml

# Optional: Other settings
TZ=UTC
PYTHONUNBUFFERED=1
```

### Persistent Data

The Docker setup includes persistent volumes for:
- **Reports**: `/guardian/reports`
- **Logs**: `/guardian/logs`
- **Data**: `/guardian/data`

Your work is automatically saved even when the container is stopped!

## 📝 Running Guardian Workflows

Once inside the container:

```bash
# List available workflows
python -m cli.main workflow list

# Run network penetration test
python -m cli.main workflow run \
  --name network_pentest \
  --target 192.168.1.100

# Run web application test
python -m cli.main workflow run \
  --name web_pentest \
  --target https://example.com

# Run with verbose output
python -m cli.main workflow run \
  --name network_pentest \
  --target 192.168.1.100 \
  --verbose

# View help
python -m cli.main --help
```

## 🧪 Testing Individual Tools

The container includes all tools pre-configured:

```bash
# Test enum4linux (null session fixed!)
enum4linux -a 192.168.1.100

# Enum4linux-ng with YAML output
enum4linux-ng.py -A 192.168.1.100 -oY output.yaml

# Nmap scan
nmap -sV -sC 192.168.1.0/24

# SQLmap
sqlmap -u "http://example.com/page?id=1" --batch

# Nikto web scan
nikto -h http://example.com

# Gobuster directory busting
gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt

# Nuclei vulnerability scan
nuclei -u http://example.com
```

## 🔒 Security Considerations

### Network Capabilities

The container requires certain capabilities for pentesting:
- `NET_ADMIN` - Network administration
- `NET_RAW` - Raw socket access (for tools like nmap)
- `SYS_ADMIN` - System administration (for certain tools)

These are **required** for pentesting tools to work properly.

### User Permissions

The Dockerfile creates a `guardian` user for non-root operation:
```bash
# Switch to guardian user inside container
su - guardian

# Or run as guardian user
docker exec -it --user guardian guardian-kali bash
```

### Host Network Access

For some tools (like network scanners), you may need host network access:
```bash
docker run -it --rm \
  --name guardian-kali \
  --network host \
  -v $(pwd):/guardian \
  guardian-cli-deluxe:kali-latest
```

⚠️ **Use host network mode only in isolated lab environments**

## 🐛 Troubleshooting

### Build Issues

**Problem**: Build fails with package installation errors
```bash
# Solution: Clean and rebuild
docker system prune -a
./docker-build-run.sh build
```

**Problem**: "No space left on device"
```bash
# Solution: Clean up Docker
docker system prune -a --volumes
```

### Runtime Issues

**Problem**: Container exits immediately
```bash
# Check logs
docker logs guardian-kali

# Run with tail to keep alive
docker run -d guardian-cli-deluxe:kali-latest tail -f /dev/null
```

**Problem**: Tools not found
```bash
# Verify installation
docker exec guardian-kali which enum4linux
docker exec guardian-kali which nmap

# Rebuild if needed
./docker-build-run.sh clean
./docker-build-run.sh build
```

**Problem**: Enum4linux still prompts for password
```bash
# This is fixed in the Dockerfile!
# But verify:
docker exec guardian-kali enum4linux -a <target>
# Should NOT prompt for password
```

### Permission Issues

**Problem**: Permission denied errors
```bash
# Fix ownership inside container
docker exec guardian-kali chown -R guardian:guardian /guardian

# Or run as root
docker exec -it --user root guardian-kali bash
```

## 📊 Image Size and Performance

- **Base Image**: ~2 GB
- **Final Image**: ~5-6 GB (with all tools)
- **Build Time**: 15-30 minutes (depending on connection)
- **Runtime Memory**: Recommended 4GB minimum, 8GB optimal

### Optimization Tips

1. **Use BuildKit** (faster builds):
   ```bash
   DOCKER_BUILDKIT=1 docker build -f Dockerfile.kali .
   ```

2. **Use .dockerignore** (included) to exclude unnecessary files

3. **Multi-stage builds** are already implemented in the Dockerfile

4. **Layer caching** is optimized in the build order

## 🔄 Updating

### Update Tools

```bash
# Enter container
docker exec -it guardian-kali bash

# Update Kali packages
sudo apt-get update && sudo apt-get upgrade -y

# Update Python packages
pip install --upgrade anthropic langchain
```

### Rebuild Image

```bash
# Pull latest Kali base
docker pull kalilinux/kali-rolling:latest

# Rebuild without cache
docker build --no-cache -f Dockerfile.kali -t guardian-cli-deluxe:kali-latest .

# Or use the script
./docker-build-run.sh clean
./docker-build-run.sh build
```

## 📚 Additional Resources

- **Guardian CLI Deluxe**: https://github.com/steveschofield/guardian-cli-deluxe
- **Kali Linux Docker**: https://www.kali.org/docs/containers/official-kalilinux-docker-images/
- **Docker Documentation**: https://docs.docker.com/
- **Penetration Testing**: https://www.offensive-security.com/

## 🆘 Support

### Getting Help

1. **Check the logs**: `docker logs guardian-kali`
2. **Verify tools**: `docker exec guardian-kali which <tool>`
3. **Test manually**: `docker exec -it guardian-kali bash`
4. **Rebuild**: `./docker-build-run.sh clean && ./docker-build-run.sh build`
5. **Open an issue**: https://github.com/steveschofield/guardian-cli-deluxe/issues

### Common Questions

**Q: Do I need Docker Desktop?**
A: No, Docker Engine is sufficient. Docker Desktop is optional.

**Q: Can I run this on Windows/Mac?**
A: Yes! Docker works on Windows, Mac, and Linux.

**Q: How do I update Guardian code?**
A: The current directory is mounted at `/guardian`, so changes are live.

**Q: Can I add more tools?**
A: Yes! Edit Dockerfile.kali and rebuild, or install tools manually in the container.

**Q: Is this production-ready?**
A: Yes! This Dockerfile includes proper security, optimization, and best practices.

## ⚖️ Legal Notice

**IMPORTANT**: Guardian CLI Deluxe is for **authorized testing only**.

✅ **Legal Use**:
- Your own systems
- Systems you have written permission to test
- Educational lab environments
- Authorized penetration tests

❌ **Illegal Use**:
- Unauthorized system access
- Malicious activities
- Systems without explicit permission

**You are fully responsible** for ensuring compliance with all applicable laws.

## 📄 License

This Dockerfile and associated scripts are part of Guardian CLI Deluxe.
See the main project LICENSE file for details.

---

**Built with ❤️ for the security community**

🛡️ Happy (Ethical) Hacking! 🛡️
