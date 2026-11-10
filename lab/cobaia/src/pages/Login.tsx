import { useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { supabase } from "../lib/supabase";

export function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [erro, setErro] = useState("");
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  async function entrar() {
    const { error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) {
      const { data } = await supabase.rpc("email_exists", { _email: email });
      setErro(data ? "Senha incorreta." : "Usuário não encontrado.");
      return;
    }
    navigate(searchParams.get("next") ?? "/");
  }

  return (
    <form onSubmit={(e) => { e.preventDefault(); entrar(); }}>
      <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="E-mail" />
      <input value={password} onChange={(e) => setPassword(e.target.value)} type="password" placeholder="Senha" />
      {erro && <p role="alert">{erro}</p>}
      <button type="submit">Entrar</button>
    </form>
  );
}
