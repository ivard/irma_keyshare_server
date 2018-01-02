-- DROP TABLE IF EXISTS users;
CREATE TABLE IF NOT EXISTS users 
(
    id int unsigned NOT NULL auto_increment PRIMARY KEY,
    username varchar(128),
    password varchar(256),
    sessionToken varchar(256),
    lastSeen long,
    pin varchar(256),
    pinCounter int,
    pinBlockDate long,
    keyshare varchar(256),
    publicKey varchar(4096),
    enrolled boolean,
    enabled boolean,
    email_issued boolean,
    INDEX (`username`)
);
-- INSERT INTO users VALUES (1, 'q@b.c', 'foobar', '1234-1234', '1234', 0, NULL, true, false);

-- DROP TABLE IF EXISTS log_entry_records;
CREATE TABLE IF NOT EXISTS log_entry_records
(
    id int unsigned NOT NULL auto_increment PRIMARY KEY,
    time long,
    event varchar(256),
    param int,
    user_id int unsigned
);

CREATE TABLE IF NOT EXISTS email_verification_records
(
    id int unsigned NOT NULL auto_increment PRIMARY KEY,
    email varchar(256) NOT NULL,
    token varchar(64) NOT NULL,
    timeout int NOT NULL,
    validity int NOT NULL,
    time_created long NOT NULL,
    time_verified long
);
