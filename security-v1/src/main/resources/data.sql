INSERT INTO `authorities`
(username, authority)
VALUES
('john', 'write');

INSERT INTO `users`
(username, password, enabled)
VALUES
('john', '$2a$10$KvlTX8lb1UVyf/FZ2x7mN.aNKraIFd0kfmHmn7uNvu.6SYoLNwiCm', '1');