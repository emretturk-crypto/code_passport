# Start with Node.js
FROM node:20-slim

# 1. Install tools
RUN apt-get update && apt-get install -y wget git tar

# 2. Install Trivy (Vulnerability Scanner)
RUN wget https://github.com/aquasecurity/trivy/releases/download/v0.48.3/trivy_0.48.3_Linux-64bit.deb
RUN dpkg -i trivy_0.48.3_Linux-64bit.deb

# 3. Install Gitleaks (Secret Scanner)
RUN wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_x64.tar.gz
RUN tar -xzf gitleaks_8.18.2_linux_x64.tar.gz
RUN mv gitleaks /usr/local/bin/
RUN chmod +x /usr/local/bin/gitleaks

# 4. Setup App
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 8080
CMD ["node", "scan.js"]