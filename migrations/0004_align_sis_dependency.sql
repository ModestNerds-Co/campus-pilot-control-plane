-- SIS admissions and enrolment reference canonical Academics structures.
UPDATE plans
SET modules_json = '["sis","academics","hr_payroll"]',
    updated_at = CURRENT_TIMESTAMP
WHERE id = 'plan_starter';
