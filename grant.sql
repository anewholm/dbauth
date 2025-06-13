CREATE USER "token_X" with CREATEROLE password 'password';
GRANT ALL ON DATABASE "winter" TO "token_X";
GRANT ALL ON SCHEMA public TO "token_X";
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO "token_X";
GRANT ALL PRIVILEGES ON ALL sequences IN SCHEMA public TO "token_X";
GRANT ALL PRIVILEGES ON ALL functions IN SCHEMA public TO "token_X";
alter user "token_X" with createrole;