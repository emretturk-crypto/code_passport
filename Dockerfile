# Start with a lightweight Node.js computer
FROM node:18-slim

# Install the Security Tools (Trivy & Git)
RUN apt-get update && apt-get install -y wget git
RUN wget https://github.com/aquasecurity/trivy/releases/download/v0.48.3/trivy_0.48.3_Linux-64bit.deb
RUN dpkg -i trivy_0.48.3_Linux-64bit.deb

# Create the working folder
WORKDIR /app

# Copy your scripts into the container
COPY package*.json ./
RUN npm install
COPY . .

# Open the door for the internet
EXPOSE 8080

# Start the engine
CMD ["node", "scan.js"]



