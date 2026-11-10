-- Storage: bucket privado, uma pasta por usuário ({user_id}/arquivo).
-- Norma: stack/supabase-rls.md R6/P2. Testes: kit/tests/sql.test.ts (contra o
-- dublê de storage — conferir no projeto real com o teste A×B de upload).

-- #region storage_policies
insert into storage.buckets (id, name, public) values ('documents', 'documents', false);

create policy "documentos: ler a própria pasta" on storage.objects for select
  to authenticated
  using (bucket_id = 'documents' and (storage.foldername(name))[1] = (select auth.uid())::text);

create policy "documentos: enviar para a própria pasta" on storage.objects for insert
  to authenticated
  with check (bucket_id = 'documents' and (storage.foldername(name))[1] = (select auth.uid())::text);

create policy "documentos: apagar da própria pasta" on storage.objects for delete
  to authenticated
  using (bucket_id = 'documents' and (storage.foldername(name))[1] = (select auth.uid())::text);
-- Sem policy de UPDATE: arquivo não é sobrescrito nem movido — envia-se outro.
-- #endregion storage_policies
