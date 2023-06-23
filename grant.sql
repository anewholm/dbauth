CREATE USER "token_38" with CREATEROLE password 'password';
GRANT ALL ON DATABaSE "winter" TO "token_38";
GRANT ALL ON SCHEMA public TO "token_38";
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO "token_38";
GRANT ALL PRIVILEGES ON ALL sequences IN SCHEMA public TO "token_38";
GRANT ALL PRIVILEGES ON ALL functions IN SCHEMA public TO "token_38";
alter user "token_38" with createrole;