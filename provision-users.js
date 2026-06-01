const https = require("https");

const TENANT_ID = process.env.AZURE_TENANT_ID;
const CLIENT_ID = process.env.AZURE_CLIENT_ID;
const CLIENT_SECRET = process.env.AZURE_CLIENT_SECRET;

const users = [
  { first: "Emma",      last: "Richardson" },
  { first: "Marcus",    last: "Chen"        },
  { first: "Sofia",     last: "Patel"       },
  { first: "Liam",      last: "O'Brien"     },
  { first: "Aisha",     last: "Johnson"     },
  { first: "Noah",      last: "Williams"    },
  { first: "Isabella",  last: "Kim"         },
  { first: "Ethan",     last: "Rodriguez"   },
  { first: "Mia",       last: "Thompson"    },
  { first: "Lucas",     last: "Schmidt"     },
  { first: "Zara",      last: "Ahmed"       },
  { first: "Oliver",    last: "Davis"       },
  { first: "Charlotte", last: "Müller"      },
  { first: "Mason",     last: "Tanaka"      },
  { first: "Amara",     last: "Singh"       },
  { first: "Benjamin",  last: "Foster"      },
  { first: "Harper",    last: "Nakamura"    },
  { first: "Alexander", last: "Volkov"      },
  { first: "Layla",     last: "Hassan"      },
  { first: "Daniel",    last: "Sullivan"    },
];

function normalizeEmail(str) {
  return str
    .toLowerCase()
    .normalize("NFD").replace(/[\u0300-\u036f]/g, "") // strip accents (ü→u, etc.)
    .replace(/[^a-z0-9]/g, "");                        // strip apostrophes, spaces, etc.
}

function post(hostname, path, headers, body) {
  return new Promise((resolve, reject) => {
    const data = typeof body === "string" ? body : new URLSearchParams(body).toString();
    const req = https.request({ hostname, path, method: "POST", headers }, (res) => {
      let raw = "";
      res.on("data", (c) => (raw += c));
      res.on("end", () => resolve({ status: res.statusCode, body: raw }));
    });
    req.on("error", reject);
    req.write(data);
    req.end();
  });
}

async function getToken() {
  const res = await post(
    "login.microsoftonline.com",
    `/${TENANT_ID}/oauth2/v2.0/token`,
    { "Content-Type": "application/x-www-form-urlencoded" },
    {
      grant_type: "client_credentials",
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      scope: "https://graph.microsoft.com/.default",
    }
  );
  const json = JSON.parse(res.body);
  if (!json.access_token) throw new Error("Token error: " + res.body);
  return json.access_token;
}

async function createUser(token, user) {
  const upn = `${normalizeEmail(user.first)}.${normalizeEmail(user.last)}@Cavalry77.onmicrosoft.com`;
  const displayName = `${user.first} ${user.last}`;
  const body = JSON.stringify({
    accountEnabled: true,
    displayName,
    givenName: user.first,
    surname: user.last,
    mailNickname: `${normalizeEmail(user.first)}.${normalizeEmail(user.last)}`,
    userPrincipalName: upn,
    passwordProfile: {
      forceChangePasswordNextSignIn: true,
      password: "Cavalry!2026",
    },
  });

  const res = await post(
    "graph.microsoft.com",
    "/v1.0/users",
    {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
      "Content-Length": Buffer.byteLength(body),
    },
    body
  );

  const ok = res.status === 201;
  const msg = ok ? "Created" : JSON.parse(res.body)?.error?.message || res.body;
  console.log(`[${ok ? "OK" : "FAIL"}] ${upn} — ${msg}`);
  return { upn, ok, msg };
}

(async () => {
  console.log("Acquiring token...");
  const token = await getToken();
  console.log("Token acquired. Provisioning 20 users...\n");

  const results = [];
  for (const user of users) {
    results.push(await createUser(token, user));
  }

  const ok = results.filter((r) => r.ok).length;
  const fail = results.length - ok;
  console.log(`\nDone. ${ok} created, ${fail} failed.`);
})();
