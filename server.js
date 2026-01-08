import express from "express";
import cors from "cors";
import fs from "fs";
import path from "path";
import archiver from "archiver";
import multer from "multer";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { GoogleGenerativeAI } from "@google/generative-ai";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));

// ================= CONFIG =================
const PORT = 3000;

// Pasta de ZIPs
const SCRIPTS_DIR = "C:/Users/Ryan/Desktop/MTA/Scirpts_Criados";
if (!fs.existsSync(SCRIPTS_DIR)) fs.mkdirSync(SCRIPTS_DIR, { recursive: true });

// Upload tmp (copiar)
const upload = multer({ dest: path.join(process.cwd(), "uploads_tmp") });

// DB simples em JSON (MVP). Depois dá pra trocar por SQLite/MySQL.
const DB_PATH = path.join(process.cwd(), "db.json");

// Gemini
if (!process.env.GEMINI_API_KEY) console.error("ERRO: GEMINI_API_KEY não encontrada no .env");
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

// Use o modelo que funcionou pra você
const GEMINI_MODEL = "gemini-2.5-flash-lite";

// JWT
const JWT_SECRET = process.env.JWT_SECRET || "change-me-now";

// ================= DB HELPERS =================
function loadDB() {
  if (!fs.existsSync(DB_PATH)) {
    const init = { users: [] };
    fs.writeFileSync(DB_PATH, JSON.stringify(init, null, 2), "utf-8");
  }
  return JSON.parse(fs.readFileSync(DB_PATH, "utf-8"));
}

function saveDB(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), "utf-8");
}

function findUserByEmail(db, email) {
  return db.users.find(u => u.email.toLowerCase() === email.toLowerCase());
}

// ================= SECURITY =================
function hashPassword(password, salt) {
  // pbkdf2: forte o suficiente pra MVP
  const hash = crypto.pbkdf2Sync(password, salt, 120000, 32, "sha256").toString("hex");
  return hash;
}

function issueToken(user) {
  return jwt.sign(
    { sub: user.id, email: user.email, plan: user.plan },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function authMiddleware(req, res, next) {
  // aceita header Authorization OU query token (pra download)
  const header = req.headers.authorization || "";
  const bearer = header.startsWith("Bearer ") ? header.slice(7) : "";
  const token = bearer || req.query.token || "";

  if (!token) return res.status(401).json({ erro: "Sem token." });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ erro: "Token inválido." });
  }
}

// gating por plano
function requirePlan(minPlan) {
  const rank = { none: 0, basic: 1, advanced: 2 };
  return (req, res, next) => {
    const plan = req.user?.plan || "none";
    if (rank[plan] >= rank[minPlan]) return next();
    return res.status(403).json({ erro: "Plano insuficiente." });
  };
}

// sempre manter o plan atualizado do DB (porque o JWT pode estar velho)
function refreshUserFromDB(req, res, next) {
  const db = loadDB();
  const user = db.users.find(u => u.id === req.user.sub);
  if (!user) return res.status(401).json({ erro: "Usuário não encontrado." });

  req.userDb = user;
  // sincroniza no req.user também
  req.user.plan = user.plan;
  next();
}

// ================= MTA / IA HELPERS =================
function normalizeBaseName(name) {
  return (name || "script_mta")
    .trim()
    .replace(/[^\w\-]+/g, "_")
    .replace(/_+/g, "_")
    .slice(0, 40) || "script_mta";
}

function nowStamp() {
  const d = new Date();
  const p2 = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p2(d.getMonth()+1)}-${p2(d.getDate())}_${p2(d.getHours())}-${p2(d.getMinutes())}-${p2(d.getSeconds())}`;
}

function extractJson(text) {
  if (!text) return null;
  const cleaned = text.trim();

  // parse direto
  try { return JSON.parse(cleaned); } catch {}

  // dentro de ```json
  const m = cleaned.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (m && m[1]) {
    try { return JSON.parse(m[1].trim()); } catch {}
  }

  // primeira { ... }
  const first = cleaned.indexOf("{");
  const last = cleaned.lastIndexOf("}");
  if (first !== -1 && last !== -1 && last > first) {
    try { return JSON.parse(cleaned.slice(first, last + 1)); } catch {}
  }

  return null;
}

async function callGeminiForFiles(prompt) {
  const system = `
Você é um gerador profissional de resources para MTA:SA (Lua).
Regras:
- Responda APENAS sobre MTA:SA.
- Você DEVE responder SOMENTE um JSON válido:
{
  "metaXml": "<meta>...</meta>",
  "serverLua": "conteudo do server.lua",
  "clientLua": "conteudo do client.lua (pode ser vazio se não precisar)",
  "readme": "opcional"
}
- metaXml deve incluir server.lua e client.lua se clientLua não for vazio.
- Código limpo, comentado e funcional.
`;

  const model = genAI.getGenerativeModel({ model: GEMINI_MODEL });
  const result = await model.generateContent(system + "\n\nPedido:\n" + prompt);
  const text = result?.response?.text?.() || "";

  const json = extractJson(text);
  if (!json) throw new Error("A IA não retornou JSON válido. Tente detalhar melhor o pedido.");

  return {
    metaXml: json.metaXml || "",
    serverLua: json.serverLua || "",
    clientLua: json.clientLua || "",
    readme: json.readme || ""
  };
}

async function zipFilesToDir(baseName, filesObj) {
  const zipName = `${normalizeBaseName(baseName)}_${nowStamp()}.zip`;
  const zipPath = path.join(SCRIPTS_DIR, zipName);

  await new Promise((resolve, reject) => {
    const output = fs.createWriteStream(zipPath);
    const archive = archiver("zip", { zlib: { level: 9 } });

    output.on("close", resolve);
    archive.on("error", reject);

    archive.pipe(output);

    const folder = normalizeBaseName(baseName);

    archive.append(filesObj.metaXml || "", { name: `${folder}/meta.xml` });
    archive.append(filesObj.serverLua || "", { name: `${folder}/server.lua` });

    if ((filesObj.clientLua || "").trim().length > 0) {
      archive.append(filesObj.clientLua, { name: `${folder}/client.lua` });
    }

    if ((filesObj.readme || "").trim().length > 0) {
      archive.append(filesObj.readme, { name: `${folder}/README.txt` });
    }

    archive.finalize();
  });

  return { zipName, zipPath };
}

function safeUnlink(p) { try { fs.unlinkSync(p); } catch {} }

// ================= AUTH =================
app.post("/auth/register", (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ erro: "Email e senha são obrigatórios." });

  const db = loadDB();
  if (findUserByEmail(db, email)) return res.status(400).json({ erro: "Email já cadastrado." });

  const salt = crypto.randomBytes(16).toString("hex");
  const passHash = hashPassword(password, salt);

  const user = {
    id: crypto.randomUUID(),
    email,
    salt,
    passHash,
    plan: "none" // sem plano até pagar
  };

  db.users.push(user);
  saveDB(db);

  res.json({ sucesso: true });
});

app.post("/auth/login", (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ erro: "Email e senha são obrigatórios." });

  const db = loadDB();
  const user = findUserByEmail(db, email);
  if (!user) return res.status(401).json({ erro: "Credenciais inválidas." });

  const tryHash = hashPassword(password, user.salt);
  if (tryHash !== user.passHash) return res.status(401).json({ erro: "Credenciais inválidas." });

  const token = issueToken(user);
  res.json({ token });
});

app.get("/me", authMiddleware, refreshUserFromDB, (req, res) => {
  res.json({ email: req.userDb.email, plan: req.userDb.plan });
});

// ================= BILLING (SIMULADO) =================
// No futuro: aqui você troca para Stripe/MercadoPago + webhook.
app.post("/billing/checkout", authMiddleware, refreshUserFromDB, (req, res) => {
  const { plan } = req.body || {};
  if (!["basic", "advanced"].includes(plan)) return res.status(400).json({ erro: "Plano inválido." });

  // ✅ MODO SIMULADO: ativa na hora
  const db = loadDB();
  const user = db.users.find(u => u.id === req.userDb.id);
  user.plan = plan;
  saveDB(db);

  // não precisa retornar token novo porque usamos refreshUserFromDB nas rotas
  res.json({ sucesso: true, mode: "simulated", planActivated: plan });
});

// ================= APP ROUTES (PROTEGIDAS) =================

// Chat (básico+)
app.post("/chat", authMiddleware, refreshUserFromDB, requirePlan("basic"), async (req, res) => {
  const { mensagem } = req.body || {};
  if (!mensagem || typeof mensagem !== "string") return res.status(400).json({ erro: "Mensagem inválida." });

  try {
    const system = `
Você é um assistente especialista em scripts Lua para MTA:SA.
Responda apenas sobre MTA:SA.
`;
    const model = genAI.getGenerativeModel({ model: GEMINI_MODEL });
    const result = await model.generateContent(system + "\n\nUsuário:\n" + mensagem);
    const text = result?.response?.text?.() || "";
    res.json({ resposta: text || "⚠️ Sem resposta." });
  } catch (err) {
    console.error("ERRO /chat:", err);
    res.status(500).json({ erro: err?.message || "Erro ao comunicar com a IA." });
  }
});

// Criar ZIP com IA (básico+)
app.post("/criar", authMiddleware, refreshUserFromDB, requirePlan("basic"), async (req, res) => {
  const { nome, desc, pedido } = req.body || {};
  const baseName = nome || "script_mta";

  const prompt =
`NOME DO RESOURCE: ${nome || "sem nome"}
DESCRIÇÃO: ${desc || "sem descrição"}
PEDIDO DO USUÁRIO:
${pedido || "(vazio)"}
`;

  try {
    const files = await callGeminiForFiles(prompt);
    const { zipName, zipPath } = await zipFilesToDir(baseName, files);
    res.json({ sucesso: true, zipName, zipPath });
  } catch (err) {
    console.error("ERRO /criar:", err);
    res.status(500).json({ erro: err?.message || "Falha ao gerar ZIP via IA." });
  }
});

// Copiar (somente advanced)
app.post("/copiar", authMiddleware, refreshUserFromDB, requirePlan("advanced"), upload.array("files"), async (req, res) => {
  const files = req.files || [];
  if (!files.length) return res.status(400).json({ erro: "Nenhum arquivo enviado." });

  try {
    const contents = [];
    for (const f of files) {
      const data = fs.readFileSync(f.path, "utf-8");
      contents.push({ name: f.originalname, text: data });
      safeUnlink(f.path);
    }

    const baseName = req.body?.nome || "script_copiado";

    const prompt =
`Você vai receber arquivos de um resource MTA:SA (meta.xml e .lua).
Tarefa:
- Criar uma versão quase idêntica (mesma lógica), mas com organização e comentários.
- Responda SOMENTE JSON no formato:
{
  "metaXml": "...",
  "serverLua": "...",
  "clientLua": "...",
  "readme": "..."
}

ARQUIVOS:
${contents.map(c => `--- ${c.name} ---\n${c.text}\n`).join("\n")}
`;

    const filesOut = await callGeminiForFiles(prompt);
    const { zipName, zipPath } = await zipFilesToDir(baseName, filesOut);

    res.json({ sucesso: true, zipName, zipPath });
  } catch (err) {
    console.error("ERRO /copiar:", err);
    res.status(500).json({ erro: err?.message || "Falha ao copiar/analisar via IA." });
  }
});

// Histórico real (básico+)
app.get("/historico", authMiddleware, refreshUserFromDB, requirePlan("basic"), (req, res) => {
  try {
    const items = fs.readdirSync(SCRIPTS_DIR)
      .filter(n => n.toLowerCase().endsWith(".zip"))
      .map(name => {
        const full = path.join(SCRIPTS_DIR, name);
        const st = fs.statSync(full);
        return { name, mtime: st.mtimeMs, size: st.size };
      })
      .sort((a,b) => b.mtime - a.mtime);

    res.json({ sucesso: true, items });
  } catch (err) {
    console.error("ERRO /historico:", err);
    res.status(500).json({ erro: "Falha ao listar histórico." });
  }
});

// Download (básico+)
// aceita token por query (?token=...) porque o front está assim
app.get("/download/:name", authMiddleware, refreshUserFromDB, requirePlan("basic"), (req, res) => {
  try {
    const name = req.params.name;

    if (!name || !name.toLowerCase().endsWith(".zip")) {
      return res.status(400).send("Arquivo inválido.");
    }

    const safeName = path.basename(name); // bloqueia ../
    const fullPath = path.join(SCRIPTS_DIR, safeName);

    if (!fs.existsSync(fullPath)) {
      return res.status(404).send("Arquivo não encontrado.");
    }

    res.download(fullPath, safeName);
  } catch (e) {
    console.error("ERRO /download:", e);
    res.status(500).send("Erro ao baixar arquivo.");
  }
});

app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
  console.log(`ZIPs em: ${SCRIPTS_DIR}`);
  console.log(`DB em: ${DB_PATH}`);
});
