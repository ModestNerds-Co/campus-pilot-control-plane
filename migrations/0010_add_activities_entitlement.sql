-- Activities owns commercial entitlement only. Activity records remain inside
-- the campus runtime and resolve canonical learner and employee identities
-- through licensed SIS and HR and payroll dependencies.
UPDATE plans
SET modules_json = '["sis","academics","attendance","activities","timetabling","messaging","finance","fees","library","learning","student_support","hr_payroll","procurement","fleet","transport","facilities","hostel","health","assets_inventory","document_registry","internal_audit","agent"]',
    updated_at = CURRENT_TIMESTAMP
WHERE id = 'plan_complete';
