const axios = require("axios");
const fs = require("fs");

const tools = JSON.parse(fs.readFileSync("./tools.json"));

async function callTool(toolName, input) {
  const tool = tools.tools.find(t => t.name === toolName);

  if (!tool) {
    throw new Error("Tool not found");
  }

  const response = await axios.post(tool.endpoint, input);
  return response.data;
}

module.exports = { callTool };