CREATE TABLE public.identity_response_audit (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    attempt_id UUID NOT NULL UNIQUE,

    alert_id TEXT,
    alert_title TEXT,
    user_upn TEXT,
    user_object_id UUID NOT NULL,

    action TEXT NOT NULL
        CHECK (action IN ('revoke_sessions', 'dismiss_risk')),

    status TEXT NOT NULL DEFAULT 'started'
        CHECK (status IN ('started', 'succeeded', 'failed', 'unknown')),

    started_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ,

    invocation_id TEXT,
    error_code TEXT,
    error_message TEXT,
    details JSONB NOT NULL DEFAULT '{}'::jsonb
);