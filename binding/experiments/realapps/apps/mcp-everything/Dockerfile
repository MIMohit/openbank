# W22 pinned MCP reference server (official @modelcontextprotocol/server-everything).
FROM node:24-alpine
RUN npm install -g @modelcontextprotocol/server-everything@2.3.0
ENV HOST=0.0.0.0 PORT=3001
EXPOSE 3001
CMD ["sh","-c","server-everything streamableHttp || npx -y @modelcontextprotocol/server-everything@2.3.0 streamableHttp"]
