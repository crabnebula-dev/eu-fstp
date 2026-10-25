/*
 * Statements whose bodies hold semicolons, quotes, comments and nested
 * dollar quotes. /* Nested comment; with 'quotes' and "identifiers". */
 */
CREATE FUNCTION greeting(who text) RETURNS text
LANGUAGE plpgsql IMMUTABLE AS $body$
DECLARE
    prefix text := 'it''s; "quoted"';  -- a comment with ' and ;
BEGIN
    /* block comment; with 'quotes' /* nested; */ still a comment */
    RETURN prefix || $inner$ $$;$$ $inner$ || who || E'\'; done';
END;
$body$;

CREATE FUNCTION add_one(i int) RETURNS int
LANGUAGE sql IMMUTABLE
BEGIN ATOMIC
    SELECT CASE WHEN i IS NULL THEN NULL ELSE i + 1 END;
END;

CREATE TABLE events (id bigserial PRIMARY KEY, note text NOT NULL);

CREATE TABLE "odd;name" ("col""quote" text DEFAULT 'x;y');

CREATE RULE accounts_log AS ON INSERT TO accounts DO ALSO (
    INSERT INTO events (note) VALUES ('account;added');
    INSERT INTO events (note) VALUES (E'second\';rule')
);

DO $$
BEGIN
    IF greeting('x;y') IS NULL THEN
        RAISE EXCEPTION 'unexpected; NULL';
    END IF;
END
$$;

-- A trailing comment without a final statement; ' " $$ /*
