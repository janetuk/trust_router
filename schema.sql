create table if not exists psk_keys (keyid text primary key, key blob, client_dh_pub raw(20));
create table if not exists authorizations( client_dh_pub raw(20), coi string, acceptor_realm string, hostname string, apc string);
create index if not exists authorizations_dhpub on authorizations( client_dh_pub);

.quit


