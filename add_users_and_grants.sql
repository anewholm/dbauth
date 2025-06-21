-- DBAuth requires these users
-- for standard connections with the database
-- by various scripting systems with different needs

-- ######################################################### artisan superuser
DROP ROLE IF EXISTS artisan;
CREATE ROLE artisan WITH
  LOGIN
  SUPERUSER
  INHERIT
  CREATEDB
  CREATEROLE
  NOREPLICATION
  BYPASSRLS
  ENCRYPTED PASSWORD 'SCRAM-SHA-256$4096:/pUw2KvgniflM/X/LmAuWg==$OUkMbupRb0ZJlkqljSAeh3YnsaOTh4Nc6s7QzyBqwR8=:r6zWmA2er1ncIhpDURcWaZOeUtxEGU7+G9ZfF8fj42s=';

-- ######################################################### create-system superuser
DROP ROLE IF EXISTS createsystem;
CREATE ROLE createsystem WITH
  LOGIN
  SUPERUSER
  INHERIT
  CREATEDB
  CREATEROLE
  NOREPLICATION
  BYPASSRLS
  ENCRYPTED PASSWORD 'SCRAM-SHA-256$4096:Lso0xmmBORGZFwtxYJS0fA==$WGk85/B0EDw48NJMhFfIExyAry9X/OnGNQ+J9notZck=:51pMvWjjz4l/rOzkQ8hpgKTOqsnUXqMj184UungUCPU=';

-- ######################################################### admin superuser => token_1
DROP ROLE IF EXISTS admin;
CREATE ROLE admin WITH
  LOGIN
  SUPERUSER
  INHERIT
  CREATEDB
  CREATEROLE
  NOREPLICATION
  BYPASSRLS
  ENCRYPTED PASSWORD 'SCRAM-SHA-256$4096:tFO/AVrREhRV5qrJ2FBmLA==$f3uYIMe9PQKsf0DAlTlXtYqP9Ixv9yJaW68+UgY8AIU=:o615b1RYpIqV4zw1viI80FIW8Iha8nvFnSIHqfEPiPY=';

DROP ROLE IF EXISTS token_1;
CREATE ROLE token_1 WITH
  LOGIN
  SUPERUSER
  INHERIT
  NOCREATEDB
  CREATEROLE
  NOREPLICATION
  NOBYPASSRLS
  ENCRYPTED PASSWORD 'SCRAM-SHA-256$4096:XEx6icTSPulwGYqS+XQ2AA==$iRjFZWMvOnyjfS9nA031X26Nv4GHH/0mZMrt0Gpeb9c=:0zN5CAA07m3bmh0twiuUa5x0OSoHgfBLUowBuyjsiMQ=';

-- ######################################################### sz superuser
DROP ROLE IF EXISTS sz;
CREATE ROLE sz WITH
  LOGIN
  SUPERUSER
  INHERIT
  CREATEDB
  CREATEROLE
  REPLICATION
  BYPASSRLS
  ENCRYPTED PASSWORD 'SCRAM-SHA-256$4096:e8EGnr5lkUqVNqLrukxIiQ==$eVkbGvIUWtvYfFZbc94ZVpCa/nrmx06UxtQqy0rRSpA=:OaRovxJhFtx7oY+t0xoU0p4vyJc1C4DbDjQaiFDK3Gs=';

-- ######################################################### frontend un-privileged user
DROP ROLE IF EXISTS frontend;
CREATE ROLE frontend WITH
  LOGIN
  NOSUPERUSER
  INHERIT
  NOCREATEDB
  NOCREATEROLE
  NOREPLICATION
  NOBYPASSRLS
  ENCRYPTED PASSWORD 'SCRAM-SHA-256$4096:YIUx8P+R6cBanZ1ALi11Yw==$QQ9Gy02uPmWezpxyCl4fnOrGnOkeDZMai1cs2Ed3LaE=:JR12OJsQB65NP9FDOJwHJ7LETCBrXU7nmSkf6EU/Bgg=';

do 
$$ 
begin
	execute format('GRANT CONNECT ON DATABASE %I TO frontend', current_database());
	grant usage on schema public to frontend;
	GRANT SELECT ON ALL TABLES IN SCHEMA public TO frontend;
	GRANT trigger ON ALL TABLES IN SCHEMA public TO frontend;
	GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO frontend;
	
	grant update, insert, delete on table public.acorn_user_throttle to frontend;
	grant update, insert, delete on table public.sessions to frontend;
	grant update, insert, delete on table public.system_event_logs to frontend;
	grant update, insert, delete on table public.system_request_logs to frontend;
	grant update, insert, delete on table public.cache to frontend;
	grant update, insert, delete on table public.cms_theme_logs to frontend;
	grant update on table public.acorn_user_users to frontend;
end;
$$;