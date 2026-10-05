-- Run as the project owner in Supabase SQL Editor before sharing the private setup page.
-- This migration does not create an invitation or modify existing accounts.
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions;

CREATE TABLE IF NOT EXISTS public.principal_setup_invitation (
  id smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  code_hash bytea NOT NULL,
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  used_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.principal_setup_invitation ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.principal_setup_invitation FROM PUBLIC, anon, authenticated;

CREATE UNIQUE INDEX IF NOT EXISTS institute_head_one_principal_username
  ON public.institute_head_profiles ((lower(username)))
  WHERE lower(username) = 'blc@principal';

CREATE OR REPLACE FUNCTION public.check_principal_setup_code(p_code text)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
BEGIN
  IF p_code IS NULL OR length(p_code) <> 64
     OR p_code !~ '^[0-9a-fA-F]{64}$' THEN
    RETURN false;
  END IF;
  RETURN EXISTS (
    SELECT 1 FROM public.principal_setup_invitation i
    WHERE i.id = 1 AND i.used_at IS NULL AND i.expires_at > now()
      AND i.code_hash = extensions.digest(lower(p_code), 'sha256')
  ) AND NOT EXISTS (
    SELECT 1 FROM public.institute_head_profiles
    WHERE lower(username) = 'blc@principal'
  );
END;
$$;

CREATE OR REPLACE FUNCTION public.claim_principal_setup(
  p_code text, p_first_name text, p_last_name text
)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE
  v_id uuid := auth.uid();
  v_email text;
  v_confirmed_at timestamptz;
  v_first text := btrim(coalesce(p_first_name, ''));
  v_last text := btrim(coalesce(p_last_name, ''));
BEGIN
  IF v_id IS NULL THEN
    RAISE EXCEPTION 'Confirm your email and sign in before completing setup.';
  END IF;
  IF length(v_first) NOT BETWEEN 2 AND 80 OR length(v_last) NOT BETWEEN 1 AND 80 THEN
    RAISE EXCEPTION 'Enter your first and last name.';
  END IF;
  IF p_code IS NULL OR length(p_code) <> 64
     OR p_code !~ '^[0-9a-fA-F]{64}$' THEN
    RAISE EXCEPTION 'Invalid setup code.';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtext('blc-principal-one-time-claim'));
  SELECT u.email, u.email_confirmed_at INTO v_email, v_confirmed_at
  FROM auth.users u WHERE u.id = v_id;
  IF v_email IS NULL OR v_confirmed_at IS NULL THEN
    RAISE EXCEPTION 'Confirm your email address before completing setup.';
  END IF;
  IF EXISTS (SELECT 1 FROM public.staff_profiles WHERE id = v_id) THEN
    RAISE EXCEPTION 'A Staff account cannot be used as the Principal account.';
  END IF;
  IF EXISTS (SELECT 1 FROM public.institute_head_profiles
             WHERE lower(username) = 'blc@principal') THEN
    RAISE EXCEPTION 'The Principal account has already been created.';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM public.principal_setup_invitation i
    WHERE i.id = 1 AND i.used_at IS NULL AND i.expires_at > now()
      AND i.code_hash = extensions.digest(lower(p_code), 'sha256')
  ) THEN
    RAISE EXCEPTION 'The private setup code is invalid or has expired.';
  END IF;

  INSERT INTO public.institute_head_profiles
    (id, username, first_name, last_name, designation, email,
     account_status, is_test_account)
  VALUES
    (v_id, 'BLC@Principal', v_first, v_last, 'Principal-cum-Secretary',
     lower(v_email), 'active', false);

  UPDATE public.principal_setup_invitation
  SET used_at = now(), used_by = v_id WHERE id = 1;
  RETURN 'BLC@Principal';
END;
$$;

REVOKE ALL ON FUNCTION public.check_principal_setup_code(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.claim_principal_setup(text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.check_principal_setup_code(text) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.claim_principal_setup(text,text,text) TO authenticated;

-- After the test Principal is removed and the setup page is deployed, run this
-- separately. Copy the returned code once and hand it privately to the Principal.
-- The code is never stored in plaintext in the database or website source.
-- WITH secret AS (
--   SELECT encode(extensions.gen_random_bytes(32), 'hex') AS code
-- ), saved AS (
--   INSERT INTO public.principal_setup_invitation(id, code_hash, expires_at)
--   SELECT 1, extensions.digest(code, 'sha256'), now() + interval '48 hours'
--   FROM secret
--   ON CONFLICT (id) DO UPDATE
--     SET code_hash = EXCLUDED.code_hash, expires_at = EXCLUDED.expires_at,
--         used_at = NULL, used_by = NULL, created_at = now()
--   RETURNING id
-- )
-- SELECT code FROM secret, saved;
