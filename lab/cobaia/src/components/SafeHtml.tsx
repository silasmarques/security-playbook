import DOMPurify from "dompurify";

const CONFIG = { ALLOWED_TAGS: ["p", "br", "strong", "em", "ul", "ol", "li", "code", "a"], ALLOWED_ATTR: ["href"] };

export function SafeHtml({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html, CONFIG) }} />;
}
