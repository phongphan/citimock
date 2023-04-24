CREATE TABLE clients (
    uid varchar(128) NOT NULL,
    "name" varchar(255) NOT NULL,
    status varchar(16) NOT NULL,
    inserted_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    hash varchar(512) NULL,
    CONSTRAINT clients_pkey PRIMARY KEY (uid)
);

create table certificates (
    uid varchar(128) primary key,
    client_id varchar(128) not null references clients(uid),
    cert_type varchar(128) not null check (cert_type in ('xml-dsig', 'xml-enc')),
    cert text not null,
    valid_from timestamp with time zone,
    valid_to timestamp with time zone,
    deleted_at timestamp with time zone,
    inserted_at timestamp with time zone
);