REASSIGN OWNED BY "token_X" TO postgres;
REVOKE ALL ON ALL TABLES IN schema public from "token_X";
REVOKE ALL ON ALL functions IN schema public from "token_X";
REVOKE ALL ON ALL sequences IN schema public from "token_X";
REVOKE ALL ON schema public from "token_X";
REVOKE ALL ON database winter from "token_X";
DROP USER if exists "token_X";

