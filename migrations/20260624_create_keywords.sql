CREATE TABLE keywords (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    category VARCHAR(100),
    content VARCHAR(255) NOT NULL UNIQUE
);

INSERT INTO keywords (category, content) VALUES
    ('Professional', 'Job'),
    ('Professional', 'interview'),
    ('Academic', 'test'),
    ('Academic', 'professor'),
    ('Academic', 'classroom'),
    ('Academic', 'Dr.'),
    ('Academic', 'exam'),
    ('Academic', 'hall'),
    ('Logistics', 'time'),
    ('Logistics', 'venue'),
    ('Logistics', 'floor'),
    ('Logistics', 'address'),
    ('Professional', 'doctor')
ON CONFLICT (content) DO NOTHING;