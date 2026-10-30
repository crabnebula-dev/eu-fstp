CREATE FUNCTION fstp_meta.apply_grant(privs text, object text, suffix text) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  cell text := current_setting('fstp.cell');
  schema_part text;
  table_part text;
  grantee text;
BEGIN
  IF cell IS NULL OR cell !~ '^[0-9a-f]{32}$' THEN RAISE EXCEPTION 'bad cell id'; END IF;
  IF current_database() NOT IN ('c_' || cell, 'v_' || cell) THEN RAISE EXCEPTION 'bad cell id'; END IF;
  IF privs IS NULL OR privs !~ '^(SELECT|INSERT|UPDATE|DELETE)(, (SELECT|INSERT|UPDATE|DELETE))*$' THEN RAISE EXCEPTION 'bad privileges'; END IF;
  IF object IS NULL OR object !~ '^[a-z_]{1,30}\.[a-z_]{1,30}$' THEN RAISE EXCEPTION 'bad object'; END IF;
  IF suffix IS NULL OR suffix !~ '^(migrator|writer|app|keys|auditor|vault)$' THEN RAISE EXCEPTION 'bad role'; END IF;
  schema_part := split_part(object, '.', 1);
  table_part := split_part(object, '.', 2);
  IF NOT EXISTS (SELECT FROM pg_namespace n JOIN pg_roles r ON r.oid = n.nspowner
                 WHERE n.nspname = schema_part AND r.rolname = current_user) THEN
    RAISE EXCEPTION 'bad object';
  END IF;
  grantee := left(current_database(), 1) || '_' || cell || '_' || suffix;
  EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I', schema_part, grantee);
  EXECUTE format('GRANT %s ON %I.%I TO %I', privs, schema_part, table_part, grantee);
END $$;
REVOKE EXECUTE ON FUNCTION fstp_meta.apply_grant(text, text, text) FROM PUBLIC;
