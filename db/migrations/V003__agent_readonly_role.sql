-- =============================================================================
-- Migration V003: Clinical Agent read-only role (v3)
-- Target Instance : cymbal-health-pg-main (cymbal_health_db)
-- Security Rule   : cymbal-health-agent-sa receives SELECT ONLY on the sanitized
--                   clinical_orders_public_v view. No write verbs and no access to
--                   the base table or to confidential = 1 (Ley 1581) rows.
-- =============================================================================

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cymbal_agent_readonly') THEN
        CREATE ROLE cymbal_agent_readonly NOLOGIN;
    END IF;
END
$$;

REVOKE ALL ON TABLE public.clinical_orders FROM cymbal_agent_readonly;
REVOKE ALL ON SEQUENCE public.clinical_order_code_seq FROM cymbal_agent_readonly;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.clinical_orders_public_v FROM cymbal_agent_readonly;
GRANT SELECT ON public.clinical_orders_public_v TO cymbal_agent_readonly;

DO $$
DECLARE
    agent_iam_role TEXT;
BEGIN
    SELECT rolname INTO agent_iam_role
    FROM pg_roles
    WHERE rolname LIKE 'cymbal-health-agent-sa@%.iam'
    LIMIT 1;

    IF agent_iam_role IS NOT NULL THEN
        EXECUTE format('REVOKE ALL ON TABLE public.clinical_orders FROM %I', agent_iam_role);
        EXECUTE format('GRANT cymbal_agent_readonly TO %I', agent_iam_role);
    END IF;
END
$$;

COMMIT;
