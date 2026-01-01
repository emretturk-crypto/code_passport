# 1. Base Image: Use a lightweight Node.js version
FROM node:20-slim

# 2. Install System Tools (Git, wget, etc.)
# We need these to download the security scanners
RUN apt-get update && apt-get install -y \
    git \
    wget \
    gnupg \
    ca-certificates \
    curl \
    lsb-release \
    && rm -rf /var/lib/apt/lists/*

# 3. Install TRIVY (Security Scanner)
RUN wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add - \
    && echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | tee -a /etc/apt/sources.list.d/trivy.list \
    && apt-get update \
    && apt-get install -y trivy

# 4. Install GITLEAKS (Secret Scanner)
# We download the specific version, unzip it, and move it to /usr/local/bin
RUN wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_x64.tar.gz \
    && tar -xzf gitleaks_8.18.2_linux_x64.tar.gz \
    && mv gitleaks /usr/local/bin/ \
    && rm gitleaks_8.18.2_linux_x64.tar.gz

# 5. Create App Directory & Set Permissions
# This is crucial! We give the 'node' user ownership of this folder.
WORKDIR /usr/src/app
COPY package*.json ./

# Change ownership of the directory to the 'node' user
# so they can write temp files later.
RUN chown -R node:node /usr/src/app

# 6. Switch to the Restricted User (The "Guest")
USER node

# 7. Install Dependencies (As the node user)
RUN npm install

# 8. Copy the rest of the code (As the node user)
COPY --chown=node:node . .

# 9. Start the Server
EXPOSE 8080
CMD ["node", "scan.js"]