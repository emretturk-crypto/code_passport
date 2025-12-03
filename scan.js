# Start with a modern, stable Node.js base
FROM node:20-slim

# 1. Install Essential System Tools
RUN apt-get update && apt-get install -y \
    wget \
    git \
    curl \
    tar \
    dpkg \
    && rm -rf /var/lib/apt/lists/*

# 2. Install TRIVY (Vulnerability Scanner)
# We use dpkg for the .deb file
RUN wget https://github.com/aquasecurity/trivy/releases/download/v0.48.3/trivy_0.48.3_Linux-64bit.deb
RUN dpkg -i trivy_0.48.3_Linux-64bit.deb

# 3. Install GITLEAKS (Secret Scanner)
# Install it directly to /usr/local/bin/
RUN wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_x64.tar.gz
RUN tar -xzf gitleaks_8.18.2_linux_x64.tar.gz
RUN mv gitleaks /usr/local/bin/
RUN chmod +x /usr/local/bin/gitleaks

# Set working directory
WORKDIR /app

# Copy package files and install Node dependencies
COPY package*.json ./
RUN npm install

# Copy application code
COPY . .

# Expose port (Render default)
EXPOSE 8080

# Start the application
CMD ["node", "scan.js"]
```

#### Step 3: Final Deployment (Clear Cache)

1.  **Save both files** (`scan.js` and `Dockerfile`).
2.  **Push the changes:**
    ```bash
    git add .
    git commit -m "Revert self-install, fix Dockerfile for robust trivy/gitleaks install"
    git push