# Trust Router Configuration Files

## Configuration files

Configuration files must end with the extension `.cfg` (case sensitive). Files whose name begins with a `.` are ignored. The configuration may be split into multiple files, which must all be placed in the same directory. By default, this is the working directory from which the Trust Router was launched, but it may be changed with the `-c` or `--config-dir` command-line option. The trust router monitors the contents of the configuration directory and will reload the configuration if any configuration files are changed, added, or removed.


## Configuration format
Each configuration file is a JSON-formatted text file. Each file contains a single JSON object with one or more keys corresponding to configuration sections. Repeated sections are not permitted within a single file, but a section may appear in multiple configuration files. The order in which the sections appear is not significant.

The sections are:
  * Internal
  * Communities
  * Local Organizations
  * Peer Organizations
  * Default Servers


## Internal configuration

JSON key: `tr_internal`

This section configures the Trust Router itself. It is a JSON object with the following keys:
  * `hostname`
    * hostname the Trust Router should use to identify itself
    * default: `none`
  * `cfg_poll_interval`
    * number of seconds between attempts to poll the configuration for changes
    * default: `1`
  * `cfg_settling_time`
    * number of seconds to wait after a configuration change is detected before reloading
    * default: `5`
  * `tids_port`. OBSOLETE. Use `tid_protocol.port`.
  * `trps_port`. OBSOLETE. Use `tr_protocol.port`.
  * `trp_connect_interval`. OBSOLETE. Use `tr_protocol.connect_interval`.
  * `trp_sweep_interval`. OBSOLETE. Use `tr_protocol.sweep_interval`.
  * `trp_update_interval`. OBSOLETE. Use `tr_protocol.update_interval`.
  * `tid_request_timeout`. OBSOLETE. Use `tid_protocol.request_timeout`.
  * `tid_response_numerator`. OBSOLETE. Use `tid_protocol.response_numerator`.
  * `tid_response_denominator`. OBSOLETE. Use `tid_protocol.response_denominator`.
  * `tid_protocol`
    * `port`
      * TCP port for the Temporary Identity Protocol server
      * default: `12309`
    * `request_timeout`
      * number of seconds to wait for a reply to a TID request before assuming failure
      * default: `5`
    * `response_numerator`
    * `response_denominator`
      * fraction of non-shared-mode AAA servers to wait for before responding to a TID request, expressed as numerator and denominator of a fraction
      * default: `2/3`
  * `tr_protocol`
    * `port`
      * TCP port for the Trust Router Protocol server
      * default: `12308`
    * `connect_interval`
      * number of seconds between attempts to connect to unconnected trust peers
      * default: `10`
    * `sweep_interval`
      * number of seconds between route / community table sweeps
      * default: `30`
    * `update_interval`
      * number of seconds between scheduled updates to trust peers
      * default: `30`
  * `logging`
    * `log_threshold`
      * minimum message severity to report via syslog
      * options: debug, info, notice, warning, err, crit, alert
      * default: `info`
    * `console_threshold`
      * minimum message severity to report to the console
      * options: debug, info, notice, warning, err, crit, alert
      * default: `notice`

## Communities

JSON key: `communities`

This section contains statically defined communities. It is a JSON array of community records.

Each community record is a JSON object with the following keys:
  * `community_id`
    * name of the community
  * `type`
    * `apc` or `coi`
  * `apcs`
    * JSON array of APCs for the community
    * must be an empty array if `type` is `apc`
  * `idp_realms`
    * JSON array of IdP realms that are members of this community
    * every IdP realm must be defined in a Local Organization, either with contact information or `remote`=`yes`
  * `rp_realms`
    * JSON array of RP realms that are members of this community
  * `expiration_interval`
    * key expiration interval for this APC (in minutes)
    * only applicable if `type` is `apc`; ignored otherwise
    * default: `43200 (30 days)`
    * valid range: 11 - 129600 (90 days)


## Local Organizations

JSON key: `local_organizations`

This section constains statically configured, local organization contact information. It consists of a JSON array of organizations


Each organization is a JSON object with the following keys
  * `organization_name`
    * name of the organization
  * `realms`
    * JSON array of realms
    * not required

Each realm is a JSON object with the following keys
  * `remote`
    * If `yes`, indicates that this is a realm we know exists but for which we do not have local contact information. Used to create communities containng remote realms.
    * options: `yes` / `no`
    * not required
    * default: ``no``
  * `realm`
    * string defining the realm name
  * `identity_provider`
    * optional; if present, an IdP realm is defined with the name in the `realm` key
    * value is a JSON object with the following keys
      * `shared_config`
        * options: `yes`, `no`
      * `apcs`
        * JSON array of APC names, each a string
      * `aaa_servers`
        * JSON array of AAA server hostnames, each a string
  * `gss_names`
    * optional; if present, a service realm is defined with the name in the `realm` key
    * JSON array of GSS names that identify members of this service realm
  * `filters`
    * optional; needed to define filters for a service realm
    * value is a filter JSON object, see `Filters` for details
    * only the `tid_inbound` filter is relevant for a service realm
    * ignored unless `gss_names` is present

### Filters
  * A set of filters is defined by a JSON object with one or more keys. Each key defines a filter of its associated type.
    * `tid_inbound` - filters TID incoming requests
    * `trp_inbound` - filters route / community updates coming from peers
    * `trp_outbound` - filters route / community updates going to peers
  * the value for each of the above keys is a JSON array of filter definitions.

Each filter definition is a JSON array of filter lines, each of which has the following keys
  * `action`
    * specifies the action to be taken when this filter line matches
    * options: `accept`, `reject`
  * `specs`
    * JSON array of filter spec definitions; at least one is required
  * `realm_constraints`
    * optional; if present, a JSON array of realm constraints
    * each realm constraint is a string with wildcard prefix matching
    * constraints are attached to a TID request if this filter matches
  * `domain_constraints`
    * optional; if present, an array of domain constraints
    * each domain constraint is a string with wildcard prefix matching
    * constraints are attached to a TID request if this filter matches

Each filter spec definition is a JSON object with the following keys
  * `field`
    * string specifying the field to be used for the filter
    * the available fields depend on the filter type; allowed fields are:
      * tid_inbound
        * `realm` - IdP realm in the TID request
        * `comm` - community (APC or CoI) in the TID request
        * `rp_realm` - RP realm in the TID request
        * `original_coi` - CoI of the original TID request if it was converted to an APC
      * trp_inbound or trp_inbound
        * `info_type` - `route` or `comm`
        * `realm` - RP or IdP realm name
        * `comm` - community name
        * fields only present for `comm` info_type
          * `comm_type` - community type a message relates to (`apc` or `coi`)
          * `realm_role` - role of the realm (`rp` or `idp`)
          * `apc` - APC
          * `owner_realm` - realm of the owner of a community
          * `owner_contact` - contact email for owner of a community
        * fields only present for `route` info_type
          * `trust_router` - name of trust router sending the update
  * `match`
    * JSON string or array of strings specifying values that match this filter
    * wildcard prefix matching if first character is `*`

### Filter Application

A filter is applied by applying each filter line in the order they appear in the JSON array. If a filter line matches, its `action` is taken and no further filter lines are considered. A filter line matches if _all_ its filter specs match (i.e., filter specs are combined with boolean AND). If the `match` value for a filter spec is a string, the filter spec matches if the `field` matches that string with prefix wildcard matching. If the `match` value is an array, the filter spec matches if _any_ value in the array matches with prefix wildcard matching (i.e., multiple `match` values are combined with boolean OR).


## Peer Organizations

JSON key: `peer_organizations`

This section defines the organizations running trust routers this trust router should peer with. Depending on filters, route and community information will be shared with these peers and TID requests will be forwarded through them. The section is a JSON array of peer organizations.


Each peer organization is a JSON object with the following keys
  * `hostname`
    * string with the DNS hostname of the organization's trust router
  * `port`
    * optional; if present, an integer specifying the port for the organization's trust router
    * default: `12308`
  * `gss_names`
    * JSON array of client names associated with valid GSS credentials for the organization's trust router
    * used to authenticate / authorize the incoming TRP connection from their trust router
  * `filters`
    * see `Filters` section in Local Organizations for details
    * only `trp_inbound` and `trp_outbound` filters are relevant
    * optional, but all updates will be rejected without at least one `accept` action


## Default Servers

JSON key: `default_servers`

This section defines one or more default AAA servers to be contacted if a TID request for an unknown realm is received. It is a JSON array of AAA server hostnames.



