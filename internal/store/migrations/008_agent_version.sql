-- Build identity reported by the installed target helper.
ALTER TABLE host_facts ADD COLUMN agent_version TEXT NOT NULL DEFAULT '';
ALTER TABLE host_facts ADD COLUMN agent_build_number TEXT NOT NULL DEFAULT '';
ALTER TABLE host_facts ADD COLUMN agent_build_commit TEXT NOT NULL DEFAULT '';
ALTER TABLE host_facts ADD COLUMN agent_build_date TEXT NOT NULL DEFAULT '';
ALTER TABLE host_facts ADD COLUMN agent_build_target TEXT NOT NULL DEFAULT '';
ALTER TABLE host_facts ADD COLUMN agent_build_type TEXT NOT NULL DEFAULT '';
