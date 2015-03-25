create table if not exists psk_keys_tab(keyid text primary key, key blob, client_dh_pub raw(20), key_expiration timestamp);
create table if not exists authorizations( client_dh_pub raw(20), coi string, acceptor_realm string, hostname string, apc string);
create index if not exists authorizations_dhpub on authorizations( client_dh_pub);
create view if not exists psk_keys as select * from psk_keys_tab where  datetime(key_expiration) > datetime('now');
CREATE VIEW if not exists authorizations_keys as select keyid, authorizations.* from psk_keys join authorizations on psk_keys.client_dh_pub = authorizations.client_dh_pub;
 

.quit


