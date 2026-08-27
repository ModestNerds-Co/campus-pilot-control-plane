-- Keep seeded plan entitlements closed over known runtime module dependencies.
UPDATE plans
SET modules_json = '["sis","academics","timetabling","messaging","library","hr_payroll","fleet","hostel","health"]',
    updated_at = CURRENT_TIMESTAMP
WHERE id = 'plan_operations';
