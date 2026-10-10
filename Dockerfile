FROM node:20-alpine

WORKDIR /app

# Copy dependencies
COPY package*.json ./
RUN npm install

# Copy the sourse code
COPY . .

EXPOSE 3000

CMD ["npm", "start"]
