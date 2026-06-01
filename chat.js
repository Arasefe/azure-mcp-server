const readline = require("readline");
const { callTool } = require("./mcp-client");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

console.log("Claude MCP CLI Ready");

rl.on("line", async (input) => {
  try {
    // VERY simple routing (you can make this smarter later)
    if (input.includes("list resource groups")) {
      const res = await callTool("list_resource_groups", {});
      console.log(res);
    }

    else if (input.includes("create user")) {
      const res = await callTool("create_user", {
        upn: "testuser@yourdomain.com",
        displayName: "Test User",
        password: "Temp1234!"
      });
      console.log(res);
    }

    else if (input.includes("assign role")) {
      const res = await callTool("assign_role", {
        assignee: "testuser@yourdomain.com",
        role: "Reader",
        scope: "/subscriptions/bed57e13-0da5-4dae-a845-4cabdea1362e"
      });
      console.log(res);
    }

    else {
      console.log("Command not recognized");
    }

  } catch (err) {
    console.error(err.message);
  }
});