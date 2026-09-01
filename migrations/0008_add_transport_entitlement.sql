-- Transport owns commercial entitlement only. Learners, employees, drivers,
-- vehicles, routes, and manifests remain inside the campus runtime.
UPDATE plans
SET modules_json = '["sis","academics","attendance","timetabling","messaging","finance","fees","library","learning","student_support","hr_payroll","procurement","fleet","transport","hostel","health","assets_inventory","document_registry","internal_audit","agent"]',
    updated_at = CURRENT_TIMESTAMP
WHERE id = 'plan_complete';
