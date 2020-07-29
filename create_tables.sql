CREATE TABLE conf(
	ID INT primary key,
    conf_name varchar(15)
);

CREATE TABLE integrity(
	ID INT primary key,
    integ_name varchar(20)
);
CREATE TABLE users(
	ID INT primary key auto_increment,
    uname varchar(20) unique,
    pass_hash varchar(64),
    salt varchar(16),
    conf_label int,
    integ_label int,
    number_of_attempts int,
    last_attempt DATETIME,
    foreign key (conf_label) references conf(ID),
	foreign key (integ_label) references integrity(ID)
);

CREATE TABLE files(
	ID int primary key auto_increment,
    fname varchar(40),
    conf_label int,
    integ_label int,
    ownerID int,
	foreign key (ownerID) references users(ID),
    foreign key (conf_label) references conf(ID),
	foreign key (integ_label) references integrity(ID)
);

CREATE TABLE DAC(
	ownerID int,
    userID int,
    fileID int,
    access int,
	foreign key (access) references access_type(ID),
	foreign key (fileID) references files(ID),
	foreign key (ownerID) references users(ID),
	foreign key (userID) references users(ID)
);

CREATE TABLE access_type(
	ID int primary key,
    type_name varchar(10)
);

INSERT INTO conf(ID, conf_name) values
				(1 , 'Unclassified'),
                (2 , 'Confidential'),
                (3 , 'Secret'),
                (4 , 'TopSecret');
                
INSERT INTO integrity(ID, integ_name) values
				(1 , 'UnTrusted'),
                (2 , 'SlightlyTrusted'),
                (3 , 'Trusted'),
                (4 , 'VeryTrusted');
                
INSERT INTO access_type(ID, type_name) values
				(1 , 'read'),
                (2 , 'write'),
                (3 , 'get');
                
-- DROP TABLE DAC;
-- DROP TABLE files;
-- DROP TABLE users;
-- select * from users



                






