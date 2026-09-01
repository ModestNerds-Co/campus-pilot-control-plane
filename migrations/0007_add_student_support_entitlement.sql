-- Student Support resolves learner identity from the operational SIS at
-- runtime; no learner or case data crosses into the commercial control plane.
UPDATE plans
SET modules_json = '["sis","academics","attendance","timetabling","messaging","finance","fees","library","learning","student_support","hr_payroll","procurement","fleet","hostel","health","assets_inventory","document_registry","internal_audit","agent"]',
    updated_at = CURRENT_TIMESTAMP
WHERE id = 'plan_complete';
