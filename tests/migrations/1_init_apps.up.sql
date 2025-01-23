INSERT INTO apps (name, secret)
VALUES ('test', 'test-secret')
ON CONFLICT DO NOTHING