-- Facilities owns commercial entitlement only. Campus locations, service
-- requests, employees, work orders, completion, and inspections remain inside
-- the campus runtime. HR and payroll is its required identity dependency.
UPDATE plans
SET modules_json = '["sis","academics","attendance","timetabling","messaging","finance","fees","library","learning","student_support","hr_payroll","procurement","fleet","transport","facilities","hostel","health","assets_inventory","document_registry","internal_audit","agent"]',
    updated_at = CURRENT_TIMESTAMP
WHERE id = 'plan_complete';
