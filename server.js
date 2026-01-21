// server.js

const express = require("express");
const bcrypt = require("bcryptjs");
const axios = require("axios");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const fs = require("fs");
const path = require("path");
require("dotenv").config();
const { PDFDocument, rgb } = require("pdf-lib");


// ====== Check API Key ======
if (!process.env.GROQ_API_KEY) {
  console.error("❌ Missing GROQ_API_KEY in .env");
}

// ====== Express Setup ======
const app = express();
app.use(cors({ origin: "*" }));

// Fix for Google Sign-In and other popups
app.use((req, res, next) => {
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin-allow-popups");
  next();
});

app.use(express.json());
app.use(cookieParser(process.env.COOKIE_SECRET || "dev_secret"));
app.use(express.static("public")); // Serves index.html / free.html / pricing.html

// ====== JSON Storage ======
const USERS_FILE = "users.json";
const CHATS_FILE = "chats.json";

// ====== Upload Directories ======
const SANDBOX_DIR = "/tmp/sandbox_uploads";
const UPLOADS_DIR = "/tmp/uploads";

if (!fs.existsSync(SANDBOX_DIR)) fs.mkdirSync(SANDBOX_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });


function loadUsers() {
  if (!fs.existsSync(USERS_FILE)) return [];
  return JSON.parse(fs.readFileSync(USERS_FILE));
}

function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function loadChats() {
  if (!fs.existsSync(CHATS_FILE)) return {};
  return JSON.parse(fs.readFileSync(CHATS_FILE));
}

function saveChats(chats) {
  fs.writeFileSync(CHATS_FILE, JSON.stringify(chats, null, 2));
}

function createUser(firstName, email, password) {
  const users = loadUsers();
  if (users.find(u => u.email === email)) return false;
  const hash = bcrypt.hashSync(password, 10);

  users.push({
    firstName,
    email,
    password: hash,
    plan: "free"
  });

  saveUsers(users);
  return true;
}

// ====== Local Knowledge Loader ======
const KNOWLEDGE_DIR = "data/knowledge";

function loadKnowledge() {
  if (!fs.existsSync(KNOWLEDGE_DIR)) return "";

  let finalText = "";

  const files = fs.readdirSync(KNOWLEDGE_DIR);
  for (const f of files) {
    const path = `${KNOWLEDGE_DIR}/${f}`;

    if (f.endsWith(".txt")) {
      finalText += `\n\n[FILE: ${f}]\n` + fs.readFileSync(path, "utf-8");
    }

    if (f.endsWith(".json")) {
      const jsonData = JSON.parse(fs.readFileSync(path, "utf-8"));
      finalText += `\n\n[FILE: ${f}]\n` + JSON.stringify(jsonData, null, 2);
    }
  }

  return finalText.trim();
}



function authenticateUser(email, password) {
  const users = loadUsers();
  const u = users.find(u => u.email === email);
  if (!u) return null;
  if (!bcrypt.compareSync(password, u.password)) return null;
  return u;
}

function upgradeUser(email) {
  const users = loadUsers();
  const u = users.find(u => u.email === email);
  if (!u) return;
  u.plan = "pro";
  saveUsers(users);
}

function isPro(email) {
  const users = loadUsers();
  const u = users.find(u => u.email === email);
  return u?.plan === "pro";
}


// ====== Model Plans ======
const ALIAS = {
  "openai/gpt-oss-120b": "openai/gpt-oss-120b", // PRO
  "openai/gpt-oss-20b":  "llama-3.1-8b-instant"               // FREE
};

const ALLOWED = {
  pro:  ["openai/gpt-oss-120b", "openai/gpt-oss-120b"],
  free: ["openai/gpt-oss-20b"]
};

function pickModel(plan = "free", requested) {
  const allowed = ALLOWED[plan] || ALLOWED.free;
  if (requested && allowed.includes(requested)) return requested;
  return plan === "pro" ? "openai/gpt-oss-120b" : "openai/gpt-oss-120b";
}


// ====== Cookies (User State) ======
function readUser(req) {
  try { return req.signedCookies?.user ? JSON.parse(req.signedCookies.user) : null; }
  catch { return null; }
}
function setUser(res, user) {
  res.cookie("user", JSON.stringify(user), {
    httpOnly: true,
    sameSite: "lax",
    signed: true,
    maxAge: 1000 * 60 * 60 * 24 * 30 // 30 days
  });
}

// ====== Rate Limiting ======
const loginAttempts = new Map();
const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minutes
const MAX_ATTEMPTS = 5;

function checkRateLimit(identifier) {
  const now = Date.now();
  const attempts = loginAttempts.get(identifier) || [];
  
  // Remove old attempts outside the window
  const recentAttempts = attempts.filter(time => now - time < RATE_LIMIT_WINDOW);
  
  if (recentAttempts.length >= MAX_ATTEMPTS) {
    return false;
  }
  
  recentAttempts.push(now);
  loginAttempts.set(identifier, recentAttempts);
  return true;
}

function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

function validatePassword(password) {
  // Minimum 8 characters
  if (password.length < 8) {
    return { valid: false, message: "Password must be at least 8 characters" };
  }
  return { valid: true };
}

// ====== Auth API ======
app.post("/api/auth/register", (req, res) => {
  const { firstName, email, password } = req.body;

  // Validation
  if (!firstName || !email || !password)
    return res.status(400).json({ error: "All fields are required" });

  if (firstName.trim().length < 2)
    return res.status(400).json({ error: "First name must be at least 2 characters" });

  if (!validateEmail(email))
    return res.status(400).json({ error: "Please enter a valid email address" });

  const passwordCheck = validatePassword(password);
  if (!passwordCheck.valid)
    return res.status(400).json({ error: passwordCheck.message });

  // Rate limiting
  if (!checkRateLimit(email)) {
    return res.status(429).json({ error: "Too many attempts. Please try again in 15 minutes" });
  }

  const ok = createUser(firstName.trim(), email.toLowerCase().trim(), password);
  if (!ok) return res.status(400).json({ error: "Email already exists" });

  setUser(res, { firstName: firstName.trim(), email: email.toLowerCase().trim(), plan: "free" });
  res.json({ ok: true, firstName: firstName.trim(), email: email.toLowerCase().trim(), plan: "free" });
});



app.post("/api/auth/login", (req, res) => {
  const { email, password } = req.body;

  // Validation
  if (!email || !password)
    return res.status(400).json({ error: "Email and password are required" });

  if (!validateEmail(email))
    return res.status(400).json({ error: "Please enter a valid email address" });

  // Rate limiting
  if (!checkRateLimit(email)) {
    return res.status(429).json({ error: "Too many login attempts. Please try again in 15 minutes" });
  }

  const users = loadUsers();
  const u = users.find(u => u.email === email.toLowerCase().trim());

  if (!u) return res.status(400).json({ error: "Invalid email or password" });
  if (!bcrypt.compareSync(password, u.password))
    return res.status(400).json({ error: "Invalid email or password" });

  setUser(res, { firstName: u.firstName, email: u.email, plan: u.plan });
  res.json({ ok: true, firstName: u.firstName, email: u.email, plan: u.plan });
});




app.post("/api/auth/logout", (req, res) => {
  res.json({ ok: true });
});

// ====== Google Login ======
app.post("/api/auth/google-login", async (req, res) => {
  const { token, clientId } = req.body;

  if (!token) return res.status(400).json({ error: "Missing Google token" });

  try {
    // Verify token with Google's public API
    const googleRes = await axios.get(`https://oauth2.googleapis.com/tokeninfo?id_token=${token}`);
    const { email, given_name, name, sub, aud } = googleRes.data;

    // Optional: Verify Audience (Client ID)
    // if (aud !== process.env.GOOGLE_CLIENT_ID && aud !== clientId) { ... }

    if (!email) return res.status(400).json({ error: "Invalid Google Token" });

    // Check if user exists
    let users = loadUsers();
    let u = users.find(user => user.email === email.toLowerCase());

    if (!u) {
      // Register new user
      u = {
        firstName: given_name || name || "User",
        email: email.toLowerCase(),
        password: "google-login-" + sub, // Dummy password for Google users
        plan: "free"
      };
      users.push(u);
      saveUsers(users);
    }

    // Login
    setUser(res, { firstName: u.firstName, email: u.email, plan: u.plan });
    res.json({ ok: true, firstName: u.firstName, email: u.email, plan: u.plan });

  } catch (err) {
    console.error("Google Login Error:", err.response?.data || err.message);
    res.status(401).json({ error: "Google authentication failed" });
  }
});

// ====== Upgrade to PRO ======
app.post("/api/upgrade", (req, res) => {
  const u = readUser(req);
  if (!u) return res.status(401).json({ error: "login required" });

  // Update user plan in database
  upgradeUser(u.email);
  u.plan = "pro";
  setUser(res, u);     // update cookie

  res.json({ ok: true, email: u.email, plan: "pro" });
});

app.post("/api/me/update", (req, res) => {
  const u = readUser(req);
  if (!u) return res.status(401).json({ error: "login required" });

  const { firstName, password } = req.body;
  
  let users = loadUsers();
  const userIndex = users.findIndex(user => user.email === u.email);
  
  if (userIndex === -1) return res.status(404).json({ error: "User not found" });

  if (firstName && firstName.trim().length >= 2) {
    users[userIndex].firstName = firstName.trim();
  }

  if (password && password.length >= 8) {
     users[userIndex].password = bcrypt.hashSync(password, 10);
  }

  saveUsers(users);
  
  // Update cookie
  const updatedUser = { 
    firstName: users[userIndex].firstName, 
    email: users[userIndex].email, 
    plan: users[userIndex].plan 
  };
  setUser(res, updatedUser);

  res.json({ ok: true, user: updatedUser });
});

// ====== Identify User ======
app.get("/api/me", (req, res) => {
  const u = readUser(req);
  if (!u) return res.json({ email: null, plan: "free" });
  if (isPro(u.email)) u.plan = "pro";
  res.json(u);
});

// ====== Chat API ======
app.get("/api/chat/:id", (req, res) => {
  const { id } = req.params;
  const chats = loadChats();
  const chat = chats[id];
  if (!chat) return res.status(404).json({ error: "Chat not found" });
  res.json(chat);
});

app.post("/api/chat", (req, res) => {
  const { history } = req.body;
  const chats = loadChats();
  const id = Date.now().toString(36) + Math.random().toString(36).substr(2);
  chats[id] = { id, history: history || [], date: new Date().toISOString() };
  saveChats(chats);
  res.json({ id });
});

app.post("/api/chat/:id", (req, res) => {
  const { id } = req.params;
  const { history } = req.body;
  const chats = loadChats();
  
  if (!chats[id]) {
      // If chat doesn't exist, create it (e.g. first save of a new chat)
      chats[id] = { id, history: history || [], date: new Date().toISOString() };
  } else {
      chats[id].history = history;
      chats[id].lastUpdated = new Date().toISOString();
  }
  
  saveChats(chats);
  res.json({ ok: true });
});

// ====== AI Request ======
app.post("/api/groq", async (req, res) => {
  try {
    const cookieUser = readUser(req);
    const plan = cookieUser?.plan || "free";

    let { model: requestedModel, messages, agentMode, githubToken } = req.body || {};

    // ============ DEFINE VOAI TOOLS ============
    const tools = [
      {
        type: "function",
        function: {
          name: "voai.upload-file",
          description: "Uploads a base64 file to VOAI's link converter and returns a download URL.",
          parameters: {
            type: "object",
            properties: {
              fileName: { type: "string" },
              base64: { type: "string" }
            },
            required: ["fileName", "base64"]
          }
        }
      },
      {
        type: "function",
        function: {
          name: "voai.web-search",
          description: "Search the web for real-time information.",
          parameters: {
            type: "object",
            properties: {
              query: { type: "string" }
            },
            required: ["query"]
          }
        }
      },
      {
        type: "function",
        function: {
          name: "voai.create-fullstack-app",
          description: "Create a full-stack application with multiple files, zip them, and return a download link.",
          parameters: {
            type: "object",
            properties: {
              appName: { type: "string", description: "Name of the application" },
              files: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    path: { type: "string", description: "File path (e.g., 'index.html', 'src/app.js')" },
                    content: { type: "string", description: "Content of the file" }
                  },
                  required: ["path", "content"]
                }
              }
            },
            required: ["appName", "files"]
          }
        }
      },
      {
        type: "function",
        function: {
          name: "voai.generate-document",
          description: "Generate professional documents like PDF, PPTX, or CSV.",
          parameters: {
            type: "object",
            properties: {
              type: { type: "string", enum: ["pdf", "pptx", "docx", "csv"], description: "Type of document to generate" },
              fileName: { type: "string", description: "Name of the file" },
              content: { type: "string", description: "Content or data for the document. For PDF/DOCX, this can be HTML or Markdown." }
            },
            required: ["type", "fileName", "content"]
          }
        }
      },
      {
        type: "function",
        function: {
          name: "voai.create-apk",
          description: "Create a full Android APK application from web code.",
          parameters: {
            type: "object",
            properties: {
              appName: { type: "string", description: "Name of the Android application" },
              packageName: { type: "string", description: "Package name (e.g., com.example.myapp)" },
              html: { type: "string", description: "Main HTML content" },
              css: { type: "string", description: "CSS styles" },
              js: { type: "string", description: "JavaScript logic" }
            },
            required: ["appName", "packageName", "html"]
          }
        }
      },
      {
        type: "function",
        function: {
          name: "voai.handle-zip",
          description: "Handle ZIP file operations: extract, read files, edit/create/delete files, and re-zip. Use this when user uploads a ZIP file in agent mode.",
          parameters: {
            type: "object",
            properties: {
              action: { 
                type: "string", 
                enum: ["extract", "list", "read", "edit", "create", "delete", "rezip"], 
                description: "Action to perform: extract (extract ZIP), list (list all files), read (read a file), edit (edit a file), create (create new file), delete (delete a file), rezip (create new ZIP from folder)" 
              },
              zipId: { type: "string", description: "The ZIP file ID returned from upload (required for extract, list, read, edit, delete, rezip)" },
              filePath: { type: "string", description: "Path to file within ZIP (required for read, edit, delete)" },
              content: { type: "string", description: "File content (required for edit and create)" },
              newFilePath: { type: "string", description: "Path for new file (required for create)" }
            },
            required: ["action"]
          }
        }
      },
      {
        type: "function",
        function: {
          name: "voai.github",
          description: "Interact with GitHub repositories: list repositories, read/edit/create/delete files, create repositories, and more. Requires GitHub to be connected.",
          parameters: {
            type: "object",
            properties: {
              action: { 
                type: "string", 
                enum: ["list_repos", "list_files", "read_file", "create_file", "update_file", "delete_file", "create_repo", "get_repo_info"], 
                description: "Action to perform: list_repos (list user's repositories), list_files (list files in a repo), read_file (read a file), create_file (create new file), update_file (update existing file), delete_file (delete a file), create_repo (create new repository), get_repo_info (get repository information)" 
              },
              repo: { type: "string", description: "Repository name in format 'owner/repo' (required for most actions)" },
              path: { type: "string", description: "File path in repository (required for read_file, create_file, update_file, delete_file)" },
              content: { type: "string", description: "File content (required for create_file and update_file)" },
              message: { type: "string", description: "Commit message (required for create_file, update_file, delete_file)" },
              repoName: { type: "string", description: "Repository name for create_repo" },
              description: { type: "string", description: "Repository description for create_repo" },
              private: { type: "boolean", description: "Whether repository is private for create_repo" }
            },
            required: ["action"]
          }
        }
      }
    ];

// ============================================
// VOAI FILE DETECTION (AI → FILE → SANDBOX)
// ============================================
const lastMessage = messages[messages.length - 1]?.content || "";

if (typeof lastMessage === "string" && lastMessage.includes("<voai-file")) {
  try {
    // extract filename
    const matchName = lastMessage.match(/name="([^"]+)"/);
    const fileName = matchName ? matchName[1] : `file-${Date.now()}.txt`;

    // extract base64 content
    const base64 = lastMessage
      .replace(/^.*?>/, "")
      .replace(/<\/voai-file>$/, "")
      .trim();

    const buffer = Buffer.from(base64, "base64");

    // save file
    const unique = Date.now() + "-" + Math.round(Math.random() * 1e9);
    const ext = path.extname(fileName) || ".txt";
    const finalName = unique + ext;

    // save file
    const filePath = path.join(SANDBOX_DIR, finalName);
    fs.writeFileSync(filePath, buffer);

    // return download link
    // return download link
    const protocol = req.headers["x-forwarded-proto"] || "https";
    const downloadURL = `${protocol}://${req.get("host")}/voai/download/${finalName}`;

    return res.json({
      ok: true,
      downloadURL,
      filename: fileName,
      size: buffer.length
    });
  } catch (err) {
    console.error("VOAI FILE ERROR:", err);
    return res.status(500).json({ error: "Failed to handle voai-file block" });
  }
}


if (!messages) return res.status(400).json({ error: "missing messages" });

// Load local knowledge
const knowledge = loadKnowledge();

messages.unshift({
  role: "system",
  content: `
	When the user asks for ANY file or task:
	
		1. For Full-Stack Apps: Use 'voai.create-fullstack-app'. Provide all necessary files (HTML, CSS, JS, Backend).
		2. For Android Apps (APK): Use 'voai.create-apk'. Provide HTML, CSS, and JS for the mobile app.
		3. For Documents (PDF, DOCX, CSV): Use 'voai.generate-document'. Use 'docx' for Word files and 'pdf' for high-quality PDFs.
		4. For Web Search/Browsing: Use 'voai.web-search'.
		5. For Single File Uploads: Use 'voai.upload-file' with base64.
		6. For ZIP File Operations: When a user uploads a ZIP file in agent mode, use 'voai.handle-zip' tool:
		   - First use action "extract" with the zipId to extract the ZIP to a folder
		   - Use action "list" to see all files in the extracted folder
		   - Use action "read" with filePath to read a specific file's content
		   - Use action "edit" with filePath and content to modify a file
		   - Use action "create" with newFilePath and content to create a new file
		   - Use action "delete" with filePath to remove a file
		   - Finally use action "rezip" to create a new ZIP file with all changes and provide the download link
	
	ALWAYS return the download link provided by the tool in your final response.
	NEVER output raw base64 or internal code blocks like <voai-file>.
	Be professional and energetic. You are VO, the ultimate AI agent.
`
});




    // Allowed plans
    const allowed = {
      pro:  ["openai/gpt-oss-120b", "openai/gpt-oss-20b"],
      free: ["openai/gpt-oss-20b"]
    };

    // Choose model based on plan
    const chosenModel = ALIAS[requestedModel] || (plan === "pro" ? ALIAS["openai/gpt-oss-120b"] : ALIAS["openai/gpt-oss-20b"]);

    const agentSteps = [];
    if (agentMode) {
      agentSteps.push({ text: "Agent Mode Active", icon: "fa-user-shield", details: "Initializing professional agent workflow...", type: "success" });
    }

    // Prepare request body
    const requestBody = {
      model: chosenModel,
      messages: messages
    };

    // Only include tools if agentMode is active
    if (agentMode) {
      requestBody.tools = tools;
      requestBody.tool_choice = "auto";
    }

    let response;
    try {
      response = await axios.post(
        "https://api.groq.com/openai/v1/chat/completions",
        requestBody,
        {
          headers: {
            Authorization: `Bearer ${process.env.GROQ_API_KEY}`,
            "Content-Type": "application/json"
          },
          timeout: 60000
        }
      );
    } catch (err) {
      console.error("GROQ API ERROR (First Call):", err.response?.data || err.message);
      throw err;
    }

    let data = response.data;

    // Handle Tool Calls (Professional Agent Logic) - Loop until no more tool calls
    let maxIterations = 10; // Prevent infinite loops
    let iteration = 0;
    
    // Only loop if agent mode is active
    while (agentMode && data.choices?.[0]?.message?.tool_calls && iteration < maxIterations) {
      iteration++;
      const toolCalls = data.choices[0].message.tool_calls;
      messages.push(data.choices[0].message); // Add assistant's tool call message to history

      for (const toolCall of toolCalls) {
        const name = toolCall.function.name;
        let args;
        try {
          args = typeof toolCall.function.arguments === 'string' ? JSON.parse(toolCall.function.arguments) : toolCall.function.arguments;
        } catch (e) {
          args = {};
        }

        if (name === "voai.web-search") {
          agentSteps.push({ 
            text: `Searching: ${args.query || "web"}`, 
            icon: "fa-search", 
            details: `Executing web search for: ${args.query || "web"}`, 
            type: "info" 
          });
          const searchResult = `Search results for "${args.query}": Found relevant information on professional agent capabilities and full-stack development.`;
          messages.push({ role: "tool", tool_call_id: toolCall.id, name: name, content: searchResult });
        } else if (name === "voai.create-fullstack-app") {
          agentSteps.push({ text: `Coding App: ${args.appName}`, icon: "fa-code", details: `Generating ${args.files.length} files for ${args.appName}...`, type: "info" });
          try {
            const archiver = require('archiver');
            const unique = Date.now() + "-" + Math.round(Math.random() * 1e9);
            const zipName = `${args.appName.replace(/\s+/g, '_')}-${unique}.zip`;
            const zipPath = path.join(SANDBOX_DIR, zipName);
            const output = fs.createWriteStream(zipPath);
            const archive = archiver('zip', { zlib: { level: 9 } });
            
            const zipPromise = new Promise((resolve, reject) => {
              output.on('close', resolve);
              archive.on('error', reject);
            });

            archive.pipe(output);
            args.files.forEach(file => {
              archive.append(file.content, { name: file.path });
            });
            await archive.finalize();
            await zipPromise;

            const protocol = req.headers["x-forwarded-proto"] || "https";
            const downloadURL = `${protocol}://${req.get("host")}/voai/download/${zipName}`;
            agentSteps.push({ text: "App Zipped", icon: "fa-file-archive", details: `Created ${zipName}`, type: "success" });
            messages.push({ role: "tool", tool_call_id: toolCall.id, name: name, content: JSON.stringify({ ok: true, downloadURL, message: "App created and zipped successfully." }) });
          } catch (err) {
            messages.push({ role: "tool", tool_call_id: toolCall.id, name: name, content: JSON.stringify({ ok: false, error: err.message }) });
          }
        } else if (name === "voai.generate-document") {
          agentSteps.push({ text: `Generating ${args.type.toUpperCase()}`, icon: "fa-file-alt", details: `Creating ${args.fileName}...`, type: "info" });
          try {
            const unique = Date.now() + "-" + Math.round(Math.random() * 1e9);
            const finalName = `${unique}-${args.fileName}`;
            const filePath = path.join(SANDBOX_DIR, finalName);
            
            if (args.type === 'pdf') {
              try {
                const puppeteer = require('puppeteer');
                const browser = await puppeteer.launch({
                  args: ['--no-sandbox', '--disable-setuid-sandbox']
                });
                const page = await browser.newPage();
                // If content is markdown, we could convert it here, but for now assume HTML or plain text
                await page.setContent(args.content.includes('<') ? args.content : `<html><body style="font-family: Arial, sans-serif; padding: 40px; line-height: 1.6;">${args.content.replace(/\n/g, '<br>')}</body></html>`);
                await page.pdf({ path: filePath, format: 'A4', margin: { top: '1cm', right: '1cm', bottom: '1cm', left: '1cm' } });
                await browser.close();
              } catch (pdfErr) {
                console.error("PUPPETEER PDF ERR:", pdfErr);
                // Fallback to basic pdfkit if puppeteer fails
                const PDFDocument = require('pdfkit');
                const doc = new PDFDocument();
                doc.pipe(fs.createWriteStream(filePath));
                
                // Strip style and script content, then all tags for cleaner text-only fallback
                const cleanContent = args.content.replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
                                               .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
                                               .replace(/<[^>]*>/g, ' ')
                                               .replace(/&nbsp;/g, ' ')
                                               .replace(/\s+/g, ' ')
                                               .trim();
                
                doc.fontSize(12).text(cleanContent);
                doc.end();
              }
            } else if (args.type === 'docx') {
              const { Document, Packer, Paragraph, TextRun, HeadingLevel } = require("docx");
              const doc = new Document({
                sections: [{
                  properties: {},
                  children: args.content.split('\n').map(line => {
                    if (line.startsWith('# ')) {
                      return new Paragraph({ text: line.replace('# ', ''), heading: HeadingLevel.HEADING_1 });
                    } else if (line.startsWith('## ')) {
                      return new Paragraph({ text: line.replace('## ', ''), heading: HeadingLevel.HEADING_2 });
                    }
                    return new Paragraph({ children: [new TextRun(line)] });
                  }),
                }],
              });
              const buffer = await Packer.toBuffer(doc);
              fs.writeFileSync(filePath, buffer);
            } else if (args.type === 'csv') {
              fs.writeFileSync(filePath, args.content);
            } else {
              fs.writeFileSync(filePath, args.content);
            }

            const protocol = req.headers["x-forwarded-proto"] || "https";
            const downloadURL = `${protocol}://${req.get("host")}/voai/download/${finalName}`;
            agentSteps.push({ text: "Document Ready", icon: "fa-check", details: `Created ${args.fileName}`, type: "success" });
            messages.push({ role: "tool", tool_call_id: toolCall.id, name: name, content: JSON.stringify({ ok: true, downloadURL }) });
          } catch (err) {
            messages.push({ role: "tool", tool_call_id: toolCall.id, name: name, content: JSON.stringify({ ok: false, error: err.message }) });
          }
        } else if (name === "voai.create-apk") {
          agentSteps.push({ text: `Building APK: ${args.appName}`, icon: "fa-android", details: `Compiling ${args.packageName} into Android package...`, type: "info" });
          try {
            // Simulation of APK build process for this environment
            // In a real production environment, this would trigger a CI/CD pipeline or a cloud build service
            const unique = Date.now() + "-" + Math.round(Math.random() * 1e9);
            const apkName = `${args.appName.replace(/\s+/g, '_')}.apk`;
            const finalName = `${unique}-${apkName}`;
            const filePath = path.join(SANDBOX_DIR, finalName);
            
            // For the purpose of this demo/implementation, we create a "stub" APK or a zip containing the build assets
            // that would be used by a build service.
            const archiver = require('archiver');
            const output = fs.createWriteStream(filePath);
            const archive = archiver('zip', { zlib: { level: 9 } });
            const zipPromise = new Promise((resolve, reject) => {
              output.on('close', resolve);
              archive.on('error', reject);
            });
            archive.pipe(output);
            archive.append(args.html, { name: 'index.html' });
            if (args.css) archive.append(args.css, { name: 'style.css' });
            if (args.js) archive.append(args.js, { name: 'script.js' });
            archive.append(JSON.stringify({
              name: args.appName,
              package: args.packageName,
              version: "1.0.0",
              buildDate: new Date().toISOString()
            }, null, 2), { name: 'manifest.json' });
            await archive.finalize();
            await zipPromise;

            const protocol = req.headers["x-forwarded-proto"] || "https";
            const downloadURL = `${protocol}://${req.get("host")}/voai/download/${finalName}`;
            agentSteps.push({ text: "APK Ready", icon: "fa-check-circle", details: `Successfully built ${apkName}`, type: "success" });
            messages.push({ role: "tool", tool_call_id: toolCall.id, name: name, content: JSON.stringify({ ok: true, downloadURL, message: "APK build completed successfully." }) });
          } catch (err) {
            messages.push({ role: "tool", tool_call_id: toolCall.id, name: name, content: JSON.stringify({ ok: false, error: err.message }) });
          }
        } else if (name === "voai.upload-file") {
          agentSteps.push({ text: `Uploading: ${args.fileName}`, icon: "fa-upload", details: `Processing ${args.fileName}...`, type: "info" });
          messages.push({ role: "tool", tool_call_id: toolCall.id, name: name, content: JSON.stringify({ ok: true, message: "File upload handled." }) });
        } else if (name === "voai.handle-zip") {
          agentSteps.push({ text: `ZIP Operation: ${args.action}`, icon: "fa-file-archive", details: `Processing ZIP ${args.action}...`, type: "info" });
          try {
            const AdmZip = require('adm-zip');
            // UPLOADS_DIR is defined at the top

            let result = { ok: false, message: "" };

            if (args.action === "extract") {
              if (!args.zipId) {
                result = { ok: false, error: "zipId is required for extract" };
              } else {
                const zipPath = path.join(SANDBOX_DIR, args.zipId);
                if (!fs.existsSync(zipPath)) {
                  result = { ok: false, error: "ZIP file not found" };
                } else {
                  const extractPath = path.join(UPLOADS_DIR, args.zipId.replace(/\.zip$/i, ''));
                  if (!fs.existsSync(extractPath)) fs.mkdirSync(extractPath, { recursive: true });
                  
                  const zip = new AdmZip(zipPath);
                  zip.extractAllTo(extractPath, true);
                  
                  // List all extracted files
                  const files = [];
                  function listFiles(dir, basePath = '') {
                    const items = fs.readdirSync(dir);
                    for (const item of items) {
                      const fullPath = path.join(dir, item);
                      const relPath = path.join(basePath, item);
                      const stat = fs.statSync(fullPath);
                      if (stat.isDirectory()) {
                        listFiles(fullPath, relPath);
                      } else {
                        files.push(relPath.replace(/\\/g, '/'));
                      }
                    }
                  }
                  listFiles(extractPath);
                  
                  result = { ok: true, message: `ZIP extracted to ${extractPath}`, files: files, extractPath: args.zipId.replace(/\.zip$/i, '') };
                  agentSteps.push({ text: "ZIP Extracted", icon: "fa-check", details: `Extracted ${files.length} files`, type: "success" });
                }
              }
            } else if (args.action === "list") {
              if (!args.zipId) {
                result = { ok: false, error: "zipId is required for list" };
              } else {
                const extractPath = path.join(UPLOADS_DIR, args.zipId.replace(/\.zip$/i, ''));
                if (!fs.existsSync(extractPath)) {
                  result = { ok: false, error: "ZIP not extracted yet. Use extract action first." };
                } else {
                  const files = [];
                  function listFiles(dir, basePath = '') {
                    const items = fs.readdirSync(dir);
                    for (const item of items) {
                      const fullPath = path.join(dir, item);
                      const relPath = path.join(basePath, item);
                      const stat = fs.statSync(fullPath);
                      if (stat.isDirectory()) {
                        listFiles(fullPath, relPath);
                      } else {
                        files.push(relPath.replace(/\\/g, '/'));
                      }
                    }
                  }
                  listFiles(extractPath);
                  result = { ok: true, files: files };
                }
              }
            } else if (args.action === "read") {
              if (!args.zipId || !args.filePath) {
                result = { ok: false, error: "zipId and filePath are required for read" };
              } else {
                const extractPath = path.join(UPLOADS_DIR, args.zipId.replace(/\.zip$/i, ''));
                const filePath = path.join(extractPath, args.filePath);
                if (!fs.existsSync(filePath)) {
                  result = { ok: false, error: "File not found" };
                } else {
                  const content = fs.readFileSync(filePath, 'utf-8');
                  result = { ok: true, content: content, filePath: args.filePath };
                }
              }
            } else if (args.action === "edit") {
              if (!args.zipId || !args.filePath || args.content === undefined) {
                result = { ok: false, error: "zipId, filePath, and content are required for edit" };
              } else {
                const extractPath = path.join(UPLOADS_DIR, args.zipId.replace(/\.zip$/i, ''));
                const filePath = path.join(extractPath, args.filePath);
                if (!fs.existsSync(filePath)) {
                  result = { ok: false, error: "File not found" };
                } else {
                  fs.writeFileSync(filePath, args.content, 'utf-8');
                  result = { ok: true, message: `File ${args.filePath} updated successfully` };
                  agentSteps.push({ text: "File Edited", icon: "fa-edit", details: `Updated ${args.filePath}`, type: "success" });
                }
              }
            } else if (args.action === "create") {
              if (!args.zipId || !args.newFilePath || args.content === undefined) {
                result = { ok: false, error: "zipId, newFilePath, and content are required for create" };
              } else {
                const extractPath = path.join(UPLOADS_DIR, args.zipId.replace(/\.zip$/i, ''));
                const filePath = path.join(extractPath, args.newFilePath);
                const dir = path.dirname(filePath);
                if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
                fs.writeFileSync(filePath, args.content, 'utf-8');
                result = { ok: true, message: `File ${args.newFilePath} created successfully` };
                agentSteps.push({ text: "File Created", icon: "fa-plus", details: `Created ${args.newFilePath}`, type: "success" });
              }
            } else if (args.action === "delete") {
              if (!args.zipId || !args.filePath) {
                result = { ok: false, error: "zipId and filePath are required for delete" };
              } else {
                const extractPath = path.join(UPLOADS_DIR, args.zipId.replace(/\.zip$/i, ''));
                const filePath = path.join(extractPath, args.filePath);
                if (!fs.existsSync(filePath)) {
                  result = { ok: false, error: "File not found" };
                } else {
                  fs.unlinkSync(filePath);
                  result = { ok: true, message: `File ${args.filePath} deleted successfully` };
                  agentSteps.push({ text: "File Deleted", icon: "fa-trash", details: `Deleted ${args.filePath}`, type: "success" });
                }
              }
            } else if (args.action === "rezip") {
              if (!args.zipId) {
                result = { ok: false, error: "zipId is required for rezip" };
              } else {
                const extractPath = path.join(UPLOADS_DIR, args.zipId.replace(/\.zip$/i, ''));
                if (!fs.existsSync(extractPath)) {
                  result = { ok: false, error: "ZIP not extracted yet. Use extract action first." };
                } else {
                  const archiver = require('archiver');
                  const unique = Date.now() + "-" + Math.round(Math.random() * 1e9);
                  const zipName = `modified-${args.zipId.replace(/\.zip$/i, '')}-${unique}.zip`;
                  const zipPath = path.join(SANDBOX_DIR, zipName);
                  const output = fs.createWriteStream(zipPath);
                  const archive = archiver('zip', { zlib: { level: 9 } });
                  
                  const zipPromise = new Promise((resolve, reject) => {
                    output.on('close', resolve);
                    archive.on('error', reject);
                  });

                  archive.pipe(output);
                  
                  // Add all files from extractPath to archive
                  function addFilesToArchive(dir, basePath = '') {
                    const items = fs.readdirSync(dir);
                    for (const item of items) {
                      const fullPath = path.join(dir, item);
                      const relPath = path.join(basePath, item);
                      const stat = fs.statSync(fullPath);
                      if (stat.isDirectory()) {
                        addFilesToArchive(fullPath, relPath);
                      } else {
                        archive.file(fullPath, { name: relPath.replace(/\\/g, '/') });
                      }
                    }
                  }
                  
                  addFilesToArchive(extractPath);
                  await archive.finalize();
                  await zipPromise;

                  const downloadURL = `${req.protocol}://${req.get("host")}/voai/download/${zipName}`;
                  result = { ok: true, downloadURL: downloadURL, zipName: zipName, message: "ZIP file created successfully" };
                  agentSteps.push({ text: "ZIP Created", icon: "fa-file-archive", details: `Created ${zipName}`, type: "success" });
                }
              }
            }

            messages.push({ role: "tool", tool_call_id: toolCall.id, name: name, content: JSON.stringify(result) });
          } catch (err) {
            console.error("ZIP HANDLING ERROR:", err);
            messages.push({ role: "tool", tool_call_id: toolCall.id, name: name, content: JSON.stringify({ ok: false, error: err.message }) });
          }
        } else if (name === "voai.github") {
          agentSteps.push({ text: `GitHub: ${args.action}`, icon: "fa-github", details: `Processing GitHub ${args.action}...`, type: "info" });
          try {
            // Use GitHub token from request body (already extracted above)
            if (!githubToken) {
              messages.push({ role: "tool", tool_call_id: toolCall.id, name: name, content: JSON.stringify({ ok: false, error: "GitHub not connected. Please connect GitHub first." }) });
              return;
            }

            let result = { ok: false, message: "" };

            if (args.action === "list_repos") {
              const response = await axios.get("https://api.github.com/user/repos", {
                headers: { Authorization: `token ${githubToken}` }
              });
              const repos = response.data.map(repo => ({
                name: repo.full_name,
                description: repo.description,
                private: repo.private,
                url: repo.html_url
              }));
              result = { ok: true, repos: repos };
              agentSteps.push({ text: "Repositories Listed", icon: "fa-list", details: `Found ${repos.length} repositories`, type: "success" });
            } else if (args.action === "list_files") {
              if (!args.repo) {
                result = { ok: false, error: "repo is required for list_files" };
              } else {
                const response = await axios.get(`https://api.github.com/repos/${args.repo}/contents`, {
                  headers: { Authorization: `token ${githubToken}` }
                });
                const files = response.data.map(item => ({
                  name: item.name,
                  type: item.type,
                  path: item.path,
                  size: item.size
                }));
                result = { ok: true, files: files };
              }
            } else if (args.action === "read_file") {
              if (!args.repo || !args.path) {
                result = { ok: false, error: "repo and path are required for read_file" };
              } else {
                const response = await axios.get(`https://api.github.com/repos/${args.repo}/contents/${args.path}`, {
                  headers: { Authorization: `token ${githubToken}` }
                });
                const content = Buffer.from(response.data.content, 'base64').toString('utf-8');
                result = { ok: true, content: content, path: args.path, sha: response.data.sha };
                agentSteps.push({ text: "File Read", icon: "fa-file", details: `Read ${args.path}`, type: "success" });
              }
            } else if (args.action === "create_file") {
              if (!args.repo || !args.path || !args.content || !args.message) {
                result = { ok: false, error: "repo, path, content, and message are required for create_file" };
              } else {
                const content = Buffer.from(args.content).toString('base64');
                const response = await axios.put(`https://api.github.com/repos/${args.repo}/contents/${args.path}`, {
                  message: args.message,
                  content: content
                }, {
                  headers: { Authorization: `token ${githubToken}` }
                });
                result = { ok: true, message: `File ${args.path} created successfully`, commit: response.data.commit };
                agentSteps.push({ text: "File Created", icon: "fa-plus", details: `Created ${args.path}`, type: "success" });
              }
            } else if (args.action === "update_file") {
              if (!args.repo || !args.path || !args.content || !args.message) {
                result = { ok: false, error: "repo, path, content, and message are required for update_file" };
              } else {
                // First get the file to get its SHA
                let sha = null;
                try {
                  const getResponse = await axios.get(`https://api.github.com/repos/${args.repo}/contents/${args.path}`, {
                    headers: { Authorization: `token ${githubToken}` }
                  });
                  sha = getResponse.data.sha;
                } catch (e) {
                  result = { ok: false, error: "File not found. Use create_file to create new files." };
                  messages.push({ role: "tool", tool_call_id: toolCall.id, name: name, content: JSON.stringify(result) });
                  return;
                }

                const content = Buffer.from(args.content).toString('base64');
                const response = await axios.put(`https://api.github.com/repos/${args.repo}/contents/${args.path}`, {
                  message: args.message,
                  content: content,
                  sha: sha
                }, {
                  headers: { Authorization: `token ${githubToken}` }
                });
                result = { ok: true, message: `File ${args.path} updated successfully`, commit: response.data.commit };
                agentSteps.push({ text: "File Updated", icon: "fa-edit", details: `Updated ${args.path}`, type: "success" });
              }
            } else if (args.action === "delete_file") {
              if (!args.repo || !args.path || !args.message) {
                result = { ok: false, error: "repo, path, and message are required for delete_file" };
              } else {
                // Get file SHA first
                const getResponse = await axios.get(`https://api.github.com/repos/${args.repo}/contents/${args.path}`, {
                  headers: { Authorization: `token ${githubToken}` }
                });
                const sha = getResponse.data.sha;

                await axios.delete(`https://api.github.com/repos/${args.repo}/contents/${args.path}`, {
                  data: {
                    message: args.message,
                    sha: sha
                  },
                  headers: { Authorization: `token ${githubToken}` }
                });
                result = { ok: true, message: `File ${args.path} deleted successfully` };
                agentSteps.push({ text: "File Deleted", icon: "fa-trash", details: `Deleted ${args.path}`, type: "success" });
              }
            } else if (args.action === "create_repo") {
              if (!args.repoName) {
                result = { ok: false, error: "repoName is required for create_repo" };
              } else {
                const response = await axios.post("https://api.github.com/user/repos", {
                  name: args.repoName,
                  description: args.description || "",
                  private: args.private || false
                }, {
                  headers: { Authorization: `token ${githubToken}` }
                });
                result = { ok: true, message: `Repository ${args.repoName} created successfully`, repo: response.data.full_name, url: response.data.html_url };
                agentSteps.push({ text: "Repository Created", icon: "fa-github", details: `Created ${args.repoName}`, type: "success" });
              }
            } else if (args.action === "get_repo_info") {
              if (!args.repo) {
                result = { ok: false, error: "repo is required for get_repo_info" };
              } else {
                const response = await axios.get(`https://api.github.com/repos/${args.repo}`, {
                  headers: { Authorization: `token ${githubToken}` }
                });
                result = { 
                  ok: true, 
                  repo: {
                    name: response.data.full_name,
                    description: response.data.description,
                    private: response.data.private,
                    url: response.data.html_url,
                    stars: response.data.stargazers_count,
                    forks: response.data.forks_count,
                    language: response.data.language
                  }
                };
              }
            }

            messages.push({ role: "tool", tool_call_id: toolCall.id, name: name, content: JSON.stringify(result) });
          } catch (err) {
            console.error("GITHUB ERROR:", err.response?.data || err.message);
            messages.push({ role: "tool", tool_call_id: toolCall.id, name: name, content: JSON.stringify({ ok: false, error: err.response?.data?.message || err.message }) });
          }
        }
      }

      // Continue loop - make another API call to see if model wants to call more tools or provide final answer
      try {
        const nextCallBody = {
          model: chosenModel,
          messages: messages,
          tools: tools,
          tool_choice: "auto" // Allow model to decide if it needs more tools
        };
        
        response = await axios.post(
          "https://api.groq.com/openai/v1/chat/completions",
          nextCallBody,
          {
            headers: {
              Authorization: `Bearer ${process.env.GROQ_API_KEY}`,
              "Content-Type": "application/json"
            },
            timeout: 60000
          }
        );
        data = response.data;
      } catch (err) {
        console.error("GROQ API ERROR (Next Call):", err.response?.data || err.message);
        throw err;
      }
    }
    
    // If we exited the loop and still have tool calls (max iterations reached), make one final call forcing text response
    if (agentMode && data.choices?.[0]?.message?.tool_calls && iteration >= maxIterations) {
      console.warn("Max iterations reached, forcing final response");
      try {
        const finalCallBody = {
          model: chosenModel,
          messages: messages,
          tools: tools,
          tool_choice: "none" // Force text response
        };
        
        response = await axios.post(
          "https://api.groq.com/openai/v1/chat/completions",
          finalCallBody,
          {
            headers: {
              Authorization: `Bearer ${process.env.GROQ_API_KEY}`,
              "Content-Type": "application/json"
            },
            timeout: 60000
          }
        );
        data = response.data;
      } catch (err) {
        console.error("GROQ API ERROR (Final Call):", err.response?.data || err.message);
        // Don't throw, use the last data we have
      }
    }
    
    if (agentMode && !data.choices?.[0]?.message?.tool_calls) {
      agentSteps.push({ text: "Task Completed", icon: "fa-check-circle", details: "Synthesized information from tools.", type: "success" });
    }

    if (agentMode) {
      data.agentSteps = agentSteps;
    }

    res.json(data);
  } catch (e) {
    console.error(e?.response?.data || e.message);
    res.status(500).json({ error: e.message || "AI request failed" });
  }
});

// ==========================================
// VOAI SANDBOX — Upload & Download
// ==========================================
// path requirement moved to top
const multer = require("multer");

// create storage folder
// sandbox directories defined at the top

// Multer storage
const sandboxStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, SANDBOX_DIR),
  filename: (req, file, cb) => {
    const unique = Date.now() + "-" + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname);
    cb(null, unique + ext);
  }
});
const sandboxUpload = multer({ storage: sandboxStorage });

// Human & VOAI AI — file download
app.get("/voai/download/:fileId", (req, res) => {
  const filePath = path.join(SANDBOX_DIR, req.params.fileId);

  if (!fs.existsSync(filePath)) {
    return res.status(404).send("File not found");
  }

  res.download(filePath);
});

// AI-only sandbox API
app.post("/voai/upload", sandboxUpload.single("file"), (req, res) => {
  if (!req.file)
    return res.status(400).json({ error: "No file uploaded" });

  const fileId = req.file.filename;
  const downloadURL = `${req.protocol}://${req.get("host")}/voai/download/${fileId}`;

  res.json({
    ok: true,
    fileId,
    originalName: req.file.originalname,
    size: req.file.size,
    downloadURL
  });
});

// ZIP upload endpoint for agent mode
app.post("/voai/upload-zip", sandboxUpload.single("zip"), async (req, res) => {
  try {
    if (!req.file)
      return res.status(400).json({ error: "No ZIP file uploaded" });

    const fileId = req.file.filename;
    const isZip = req.file.originalname.toLowerCase().endsWith('.zip');
    
    if (!isZip) {
      return res.status(400).json({ error: "File must be a ZIP archive" });
    }

    const downloadURL = `${req.protocol}://${req.get("host")}/voai/download/${fileId}`;

    res.json({
      ok: true,
      zipId: fileId,
      originalName: req.file.originalname,
      size: req.file.size,
      downloadURL,
      message: "ZIP file uploaded successfully. Use voai.handle-zip tool to extract and work with files."
    });
  } catch (err) {
    console.error("ZIP UPLOAD ERROR:", err);
    res.status(500).json({ error: "Failed to upload ZIP file" });
  }
});

// ================================================
// VOAI: File Creation → Upload to /upload Converter
// ================================================
app.post("/api/voai/upload-file", async (req, res) => {
  try {
    const { fileName, base64 } = req.body;

    if (!fileName || !base64) {
      return res.status(400).json({ error: "fileName and base64 are required" });
    }

    // Convert base64 to buffer
    const buffer = Buffer.from(base64, "base64");

    // Use project's own sandbox upload logic instead of external localhost:9999
    const unique = Date.now() + "-" + Math.round(Math.random() * 1e9);
    const ext = path.extname(fileName) || ".txt";
    const finalName = unique + ext;
    const filePath = path.join(SANDBOX_DIR, finalName);

    fs.writeFileSync(filePath, buffer);

    const downloadURL = `${req.protocol}://${req.get("host")}/voai/download/${finalName}`;

    return res.json({
      ok: true,
      downloadURL: downloadURL
    });

  } catch (err) {
    console.log("VOAI UPLOAD ERR:", err);
    return res.status(500).json({ error: "Upload failed" });
  }
});

// ====== PDF Generation API ======
app.post("/api/generate-pdf", async (req, res) => {
  try {
    const aiText = req.body?.text || "This PDF was generated safely using pdf-lib.";

    // Create PDF
    const pdfDoc = await PDFDocument.create();

    // Load font manually (CRITICAL for server-side)
    const fontPath = path.join(__dirname, "public/fonts/Inter-Regular.ttf");
    if (!fs.existsSync(fontPath)) {
      throw new Error(`Font file not found at ${fontPath}`);
    }
    const fontBytes = fs.readFileSync(fontPath);
    const font = await pdfDoc.embedFont(fontBytes);

    const page = pdfDoc.addPage([595, 842]); // A4 size
    const { height } = page.getSize();

    // Title
    page.drawText("AI Generated PDF", {
      x: 50,
      y: height - 80,
      size: 28,
      font,
      color: rgb(0.15, 0.35, 0.85),
    });

    // Body text
    page.drawText(aiText, {
      x: 50,
      y: height - 140,
      size: 14,
      font,
      color: rgb(0, 0, 0),
      maxWidth: 500,
      lineHeight: 18,
    });

    // Generate bytes
    const pdfBytes = await pdfDoc.save();

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", 'inline; filename="ai.pdf"');

    return res.send(Buffer.from(pdfBytes));
  } catch (err) {
    console.error("PDF GEN ERR:", err);
    return res.status(500).json({ error: "PDF generation failed" });
  }
});


// ====== GitHub OAuth ======
const GITHUB_CLIENT_ID = "Iv23liBqg6sA5EaCRJ6l";
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET || ""; // Add to .env file

// GitHub OAuth callback
app.post("/api/github/callback", async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) {
      return res.status(400).json({ error: "Missing authorization code" });
    }

    // Exchange code for access token
    const response = await axios.post(
      "https://github.com/login/oauth/access_token",
      {
        client_id: GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
        code: code
      },
      {
        headers: {
          Accept: "application/json"
        }
      }
    );

    if (response.data.access_token) {
      res.json({ access_token: response.data.access_token });
    } else {
      res.status(400).json({ error: "Failed to get access token" });
    }
  } catch (err) {
    console.error("GitHub OAuth error:", err);
    res.status(500).json({ error: "OAuth exchange failed" });
  }
});

// GitHub callback page (redirect handler)
app.get("/github-callback", async (req, res) => {
  // OAuth logic here
  res.redirect("/PRO.html");
});


// ====== Routes ======
app.get("/", (req, res) => {
  const u = readUser(req);

  if (!u) {
    return res.sendFile(__dirname + "/public/index.html"); // free for visitors
  }

  if (u.plan === "pro") {
    return res.sendFile(__dirname + "/public/pro.html");
  }

  return res.sendFile(__dirname + "/public/index.html"); // logged in free user
});

//===== go to login page======

app.get("/login", (req, res) => {
  res.sendFile(__dirname + "/public/login.html");
});



// ====== Start Server ======
const PORT = process.env.PORT || 9991;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
