CREATE TABLE broken_partial (id int);
INSERT INTO broken_partial VALUES (1);
INSERT INTO no_such_table VALUES (1);
CREATE TABLE broken_after (id int);
