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
    block_time DATETIME,
    is_block int default 0,
    foreign key (conf_label) references conf(ID),
	foreign key (integ_label) references integrity(ID)
);


CREATE TABLE files(
	ID int auto_increment ,
    fname varchar(40) ,
    conf_label int default null,
    integ_label int default null,
    ownerID int,
    access varchar(3) default null,
    userID int default null,
    mode varchar(4),
    PRIMARY KEY (ID),
	foreign key (ownerID) references users(ID),
    foreign key (conf_label) references conf(ID),
	foreign key (userID) references users(ID),
	foreign key (integ_label) references integrity(ID)
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
                
                





                






