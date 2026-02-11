# BootCamp-Lab - Docker Deployment Guide

## Quick Start with Docker

### Prerequisites
- Docker installed
- Docker Compose installed

### Build and Run

1. **Build the Docker image:**
```bash
docker build -t BootCamp-Lab .
```

2. **Run with Docker Compose:**
```bash
docker-compose up -d
```

3. **Access the application:**
```
http://localhost:5000
```

### Docker Commands

**View logs:**
```bash
docker-compose logs -f
```

**Stop the application:**
```bash
docker-compose down
```

**Restart:**
```bash
docker-compose restart
```

**Reset (clean start):**
```bash
docker-compose down -v
rm -rf instance/ uploads/
docker-compose up -d
```

### Accessing the Container

**Open shell in container:**
```bash
docker exec -it BootCamp-Lab /bin/bash
```

**Run commands inside container:**
```bash
docker exec BootCamp-Lab whoami
docker exec BootCamp-Lab ls -la /app
```

### Network Configuration

The application runs in an isolated Docker network (`BootCamp-Lab-network`).

To access from other machines on your network:
```bash
# Find your host IP
ip addr show

# Access from other machines
http://YOUR_HOST_IP:5000
```

### Troubleshooting

**Port already in use:**
```bash
# Change port in docker-compose.yml
ports:
  - "8080:5000"  # Use port 8080 instead
```

**Permission issues:**
```bash
chmod -R 755 uploads/
chmod -R 755 instance/
```

**Database not initializing:**
```bash
docker-compose down -v
rm -rf instance/
docker-compose up -d
```

### Production-Like Deployment

For a more realistic target environment:

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  BootCamp-Lab:
    build: .
    container_name: BootCamp-Lab
    ports:
      - "80:5000"
    volumes:
      - BootCamp-Lab-data:/app/instance
      - BootCamp-Lab-uploads:/app/uploads
    environment:
      - FLASK_ENV=production
      - DEBUG=True
    restart: always
    networks:
      - BootCamp-Lab-network

volumes:
  BootCamp-Lab-data:
  BootCamp-Lab-uploads:

networks:
  BootCamp-Lab-network:
    driver: bridge
```

Run with:
```bash
docker-compose -f docker-compose.prod.yml up -d
```

### Security Note

**This Docker container is intentionally vulnerable!**
- Do NOT expose to the internet
- Use only in isolated lab environments
- Consider using Docker network isolation
- Monitor container activity during training

### Advanced Usage

**Run multiple instances for different students:**
```bash
# Student 1
docker run -d -p 5001:5000 --name BootCamp-Lab-student1 BootCamp-Lab

# Student 2
docker run -d -p 5002:5000 --name BootCamp-Lab-student2 BootCamp-Lab

# Student 3
docker run -d -p 5003:5000 --name BootCamp-Lab-student3 BootCamp-Lab
```

**Export/Import container:**
```bash
# Export
docker save BootCamp-Lab > BootCamp-Lab.tar

# Import on another machine
docker load < BootCamp-Lab.tar
```

### Cleanup

**Remove everything:**
```bash
docker-compose down -v
docker rmi BootCamp-Lab
rm -rf instance/ uploads/
```
