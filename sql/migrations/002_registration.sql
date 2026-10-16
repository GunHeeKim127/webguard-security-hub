-- Dedicated viewer-only entry point: the runtime role still has no INSERT on users.
CREATE FUNCTION public.register_viewer(p_id uuid,p_email text,p_hash text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
 IF char_length(p_email) NOT BETWEEN 3 AND 254
    OR p_email <> lower(btrim(p_email))
    OR p_email !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
    OR p_hash !~ '^[0-9a-f]{32}:[0-9a-f]{128}$'
    OR p_id IS NULL OR p_email IS NULL OR p_hash IS NULL THEN
  RAISE EXCEPTION 'Invalid registration';
 END IF;
 INSERT INTO public.users(id,email,password_hash,role)
 VALUES(p_id,p_email,p_hash,'viewer') ON CONFLICT(email) DO NOTHING;
END $$;
REVOKE ALL ON FUNCTION public.register_viewer(uuid,text,text) FROM PUBLIC;
