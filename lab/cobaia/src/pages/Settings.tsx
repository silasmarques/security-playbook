import { useState } from "react";
import { supabase } from "../lib/supabase";

export function Settings() {
  const [key, setKey] = useState(localStorage.getItem("gemini_api_key") ?? "");

  async function salvar() {
    localStorage.setItem("gemini_api_key", key);
    await supabase.functions.invoke("save-settings", { body: { geminiApiKey: key, theme: "dark" } });
  }

  return (
    <div>
      <label>Sua chave do Gemini<input value={key} onChange={(e) => setKey(e.target.value)} /></label>
      <button onClick={salvar}>Salvar</button>
    </div>
  );
}
