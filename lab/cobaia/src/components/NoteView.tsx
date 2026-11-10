import ReactMarkdown from "react-markdown";
import rehypeRaw from "rehype-raw";
import { dataBr } from "../lib/format";

interface Props { title: string; content: string; summary: string; createdAt: string }

export function NoteView({ title, content, summary, createdAt }: Props) {
  return (
    <article>
      <h1>{title}</h1>
      <small>{dataBr(new Date(createdAt))}</small>
      <ReactMarkdown rehypePlugins={[rehypeRaw]}>{content}</ReactMarkdown>
      <section>
        <h2>Resumo da IA</h2>
        <div dangerouslySetInnerHTML={{ __html: summary }} />
      </section>
    </article>
  );
}
