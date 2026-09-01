-- E-learning consumes teaching assignments, learner enrolments, employee
-- identity, and governed Document Registry resources at runtime.
UPDATE plans
SET modules_json = '["sis","academics","attendance","timetabling","messaging","finance","fees","library","learning","hr_payroll","procurement","fleet","hostel","health","assets_inventory","document_registry","internal_audit","agent"]',
    updated_at = CURRENT_TIMESTAMP
WHERE id = 'plan_complete';
