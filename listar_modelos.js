import dotenv from "dotenv";
dotenv.config();

const key = process.env.GEMINI_API_KEY;

async function main() {
  const url = `https://generativelanguage.googleapis.com/v1beta/models?key=${encodeURIComponent(key)}`;
  const r = await fetch(url);
  const data = await r.json();

  if (!r.ok) {
    console.error("Erro ao listar modelos:", data);
    process.exit(1);
  }

  const models = (data.models || []).map(m => ({
    name: m.name,
    methods: m.supportedGenerationMethods
  }));

  console.table(models);
}

main();
