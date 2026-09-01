-- Attendance consumes Academics classes and SIS enrolments at runtime.
UPDATE plans
SET modules_json = '["sis","academics","attendance","timetabling","messaging","library","hr_payroll","fleet","hostel","health"]',
    updated_at = CURRENT_TIMESTAMP
WHERE id = 'plan_operations';

UPDATE plans
SET modules_json = '["sis","academics","attendance","timetabling","messaging","finance","fees","library","hr_payroll","procurement","fleet","hostel","health","assets_inventory","document_registry","internal_audit","agent"]',
    updated_at = CURRENT_TIMESTAMP
WHERE id = 'plan_complete';
