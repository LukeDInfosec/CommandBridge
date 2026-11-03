"""
What a port scan actually means — the judgement a tester makes by eye.

Coffee Break's first stage is nmap. Before this module, the only thing
it did with the result was report the dozen or so services that were in
a hand-written list, which left the normal case — SSH on 22 with a
version banner, FTP on 21, an admin panel on 8080 — producing nothing
at all. A chain of standard checks that runs the checks and says
nothing is worse than no chain, because the tester assumes it looked.

So this is the table a tester carries in their head, written down:

  * which services are dangerous to have reachable from the internet
    and why (not "SSH is bad" — SSH exposed to the world is a
    brute-force and 0-day surface that usually should be behind a VPN
    or an allowlist),
  * which are dangerous ANYWHERE because the protocol has no transport
    security or no authentication worth the name (telnet, FTP, rsh,
    Memcached, Redis),
  * which are ordinary on an internal host but a finding when public
    (databases, Kubernetes, Docker, management consoles),
  * and which are simply expected (80, 443).

Three principles, because the hard part of this is not the list:

  1. REACHABILITY IS PART OF THE FINDING. The same open port is a
     different finding on a public IP than on 10.0.0.5. Where the
     address can be determined, the rating follows it; where it cannot,
     the finding says which assumption it made.
  2. A VERSION BANNER IS ITS OWN FINDING. The tester asked for this
     explicitly: if SSH answers with "OpenSSH 8.9p1", that is worth
     flagging whether or not the version is old, because it is what a
     CVE search starts from. Whether it is OUT OF DATE is a separate
     question, answered only from the local version catalogue and never
     guessed.
  3. NOTHING IS INVENTED. Every rating here is about exposure — the
     service answered on that port. No finding in this module claims a
     vulnerability in the service itself; that needs the service tested,
     which other stages do.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

#: Categories, each mapping to an entry in the issue library. The
#: category decides the issue key; the per-service entry decides the
#: wording and the rating.
CLEARTEXT = "cleartext_service"
DATASTORE = "exposed_datastore"
REMOTE_ACCESS = "remote_access_exposed"
ADMIN_SERVICE = "admin_service_exposed"
MANAGEMENT = "management_interface_exposed"
ORCHESTRATION = "orchestration_api_exposed"
MAIL = "mail_service_exposed"
DIRECTORY = "directory_service_exposed"
FILE_SHARE = "file_share_exposed"
LEGACY = "legacy_service_exposed"
BROKER = "message_broker_exposed"
MONITORING = "monitoring_exposed"
WEB = "web_service_observed"
OTHER = "service_exposed"


@dataclass(frozen=True)
class Service:
    """One service, and what it means that it answered."""

    name: str
    category: str
    #: Rating when the host is reachable from the internet.
    public: str
    #: Rating when the host is internal, or when reachability is unknown
    #: and the service is not dangerous in itself.
    internal: str
    #: Why it matters, in the words that go in a report.
    why: str
    #: What to do about it.
    fix: str
    #: True when the protocol is a problem wherever it runs, so the
    #: internal rating is not reduced. Telnet on an internal network is
    #: still telnet.
    dangerous_anywhere: bool = False
    #: Other ports this service is conventionally found on.
    ports: tuple = ()
    #: nmap service names that mean this entry.
    aliases: tuple = ()


#: The table. Ratings are for EXPOSURE, which is what a port scan
#: establishes — not for any vulnerability in the software.
SERVICES = (
    # ── no transport security: a problem wherever they run ──────────
    Service("FTP", CLEARTEXT, "HIGH", "MEDIUM",
            "FTP carries credentials and file contents in cleartext. "
            "Anyone able to observe the network path reads both, and "
            "anonymous access is a common default.",
            "Replace with SFTP or FTPS. If FTP must stay, restrict it to "
            "known source addresses and confirm anonymous access is off.",
            dangerous_anywhere=True, ports=(21, 990),
            aliases=("ftp", "ftp-data", "ftps")),
    Service("Telnet", CLEARTEXT, "HIGH", "HIGH",
            "Telnet has no transport security at all: the session, "
            "including the password used to start it, is readable by "
            "anyone on the path. It has no legitimate place on a modern "
            "network.",
            "Disable it and use SSH. There is no configuration that makes "
            "telnet safe.",
            dangerous_anywhere=True, ports=(23, 2323),
            aliases=("telnet",)),
    Service("rsh / rlogin / rexec", CLEARTEXT, "HIGH", "HIGH",
            "The Berkeley r-services authenticate on trusted host names "
            "and send everything in cleartext. Trust is asserted by the "
            "client, which is to say it is not authentication.",
            "Disable them and use SSH.",
            dangerous_anywhere=True, ports=(512, 513, 514),
            aliases=("exec", "login", "shell", "rsh", "rlogin", "rexec")),
    Service("TFTP", CLEARTEXT, "HIGH", "MEDIUM",
            "TFTP has no authentication and no encryption. Where it is "
            "used for device provisioning it frequently serves "
            "configuration files containing credentials.",
            "Remove it, or bind it to the provisioning VLAN only.",
            dangerous_anywhere=True, ports=(69,), aliases=("tftp",)),
    Service("SNMP", CLEARTEXT, "HIGH", "MEDIUM",
            "SNMP v1 and v2c authenticate with a community string sent in "
            "cleartext, and 'public' is still a common default. Read "
            "access alone discloses interfaces, routes, processes and "
            "often ARP tables.",
            "Move to SNMPv3 with authentication and privacy, change "
            "community strings, and restrict to the monitoring hosts.",
            dangerous_anywhere=True, ports=(161, 162), aliases=("snmp",)),
    Service("POP3 / IMAP (cleartext)", CLEARTEXT, "MEDIUM", "LOW",
            "Mailbox credentials and message contents cross the network "
            "unprotected on the cleartext ports.",
            "Offer only the implicit-TLS ports, or require STARTTLS and "
            "reject plaintext authentication.",
            ports=(110, 143), aliases=("pop3", "imap")),
    Service("Finger", LEGACY, "MEDIUM", "LOW",
            "Finger lists local user accounts and their login state to "
            "anyone who asks — a username list handed to an attacker "
            "before they start.",
            "Disable it.",
            dangerous_anywhere=True, ports=(79,), aliases=("finger",)),
    Service("X11", REMOTE_ACCESS, "HIGH", "MEDIUM",
            "An X server with access control off accepts connections that "
            "can read the screen and inject keystrokes.",
            "Bind X to the local socket only and never -nolisten off.",
            ports=(6000, 6001), aliases=("x11", "x11-ssh-offset")),

    # ── remote access: ordinary internally, a surface when public ───
    Service("SSH", REMOTE_ACCESS, "MEDIUM", "INFO",
            "SSH reachable from the internet is a continuous "
            "authentication surface: it is brute-forced constantly, it "
            "discloses its version to anyone who connects, and a "
            "pre-authentication flaw in the daemon becomes directly "
            "exploitable. The protocol is sound; the exposure is the "
            "finding.",
            "Put it behind a VPN or restrict it to known source "
            "addresses. Where it must stay public: keys only, no "
            "password authentication, no root login, and rate limiting.",
            ports=(22, 2222), aliases=("ssh",)),
    Service("RDP", REMOTE_ACCESS, "HIGH", "LOW",
            "RDP exposed to the internet is among the most reliably "
            "attacked services there is — the initial access route for a "
            "large share of ransomware incidents, through credential "
            "stuffing and through protocol flaws such as BlueKeep.",
            "Never expose RDP directly. Put it behind a VPN or an RD "
            "Gateway, and require network-level authentication and MFA.",
            ports=(3389,), aliases=("ms-wbt-server", "rdp")),
    Service("VNC", REMOTE_ACCESS, "HIGH", "MEDIUM",
            "VNC gives full interactive control of a desktop. Its own "
            "authentication is an 8-character password at best, many "
            "deployments have none, and the session is unencrypted.",
            "Tunnel it over SSH or a VPN and never expose it directly.",
            ports=(5800, 5900, 5901, 5902), aliases=("vnc", "vnc-http")),
    Service("Windows SMB", FILE_SHARE, "CRITICAL", "LOW",
            "SMB exposed to the internet is how EternalBlue, WannaCry and "
            "a decade of ransomware spread. It also leaks host and domain "
            "information before authentication.",
            "Block 139 and 445 at the perimeter without exception. "
            "Internally, require SMBv2+ with signing.",
            ports=(139, 445), aliases=("microsoft-ds", "netbios-ssn",
                                       "smb", "netbios-dgm")),
    Service("NFS", FILE_SHARE, "HIGH", "MEDIUM",
            "NFS exports are commonly readable by any host that can reach "
            "the port, with authorisation based on client-asserted UIDs.",
            "Restrict exports by address, require Kerberos (sec=krb5p), "
            "and never expose 2049 publicly.",
            ports=(2049, 111), aliases=("nfs", "rpcbind", "mountd")),
    Service("rsync", FILE_SHARE, "HIGH", "MEDIUM",
            "An rsync daemon frequently exposes modules with no "
            "authentication, allowing a full directory listing and "
            "download — and sometimes upload.",
            "Run rsync over SSH instead of as a daemon, or require "
            "auth-users and restrict hosts allow.",
            ports=(873,), aliases=("rsync",)),
    Service("IPMI / BMC", MANAGEMENT, "CRITICAL", "HIGH",
            "A baseboard management controller is below the operating "
            "system: access means power control, console and virtual "
            "media. IPMI 2.0 also has a protocol flaw that returns a "
            "password hash to an unauthenticated requester.",
            "Management interfaces belong on an isolated network, never "
            "routable from user networks and never from the internet.",
            dangerous_anywhere=True, ports=(623, 664),
            aliases=("asf-rmcp", "ipmi")),

    # ── datastores: nothing authenticates by default ────────────────
    Service("Redis", DATASTORE, "CRITICAL", "HIGH",
            "Redis has no authentication in its default configuration, "
            "and an unauthenticated instance is not just a data "
            "disclosure: CONFIG SET lets an attacker write files, which "
            "is a well-trodden path to command execution.",
            "Bind to localhost, set requirepass, enable protected-mode "
            "and rename or disable CONFIG.",
            dangerous_anywhere=True, ports=(6379, 6380),
            aliases=("redis",)),
    Service("Memcached", DATASTORE, "CRITICAL", "HIGH",
            "Memcached has no authentication and, on UDP, is one of the "
            "largest reflection amplifiers on the internet — so an "
            "exposed instance is both a data disclosure and a weapon.",
            "Bind to localhost, disable UDP (-U 0), and firewall 11211.",
            dangerous_anywhere=True, ports=(11211,),
            aliases=("memcached", "memcache")),
    Service("MongoDB", DATASTORE, "CRITICAL", "HIGH",
            "Historically MongoDB listened on all interfaces with no "
            "authentication, which is how tens of thousands of databases "
            "were ransomed. An exposed instance should be assumed "
            "readable until proven otherwise.",
            "Enable authorization, bind to the application's network "
            "only, and firewall 27017.",
            ports=(27017, 27018, 27019), aliases=("mongodb", "mongod")),
    Service("Elasticsearch", DATASTORE, "CRITICAL", "HIGH",
            "Elasticsearch shipped for years with no authentication and a "
            "full HTTP API — an exposed node usually means every index is "
            "readable, and often deletable.",
            "Enable security, require TLS and authentication, and keep "
            "9200/9300 off any public interface.",
            ports=(9200, 9300), aliases=("elasticsearch", "wap-wsp")),
    Service("MySQL / MariaDB", DATASTORE, "HIGH", "MEDIUM",
            "A database port reachable from outside the application tier "
            "is a direct authentication surface against the data itself, "
            "and version banners are returned before authentication.",
            "Bind to the application network, require TLS, and firewall "
            "3306.",
            ports=(3306, 3307), aliases=("mysql", "mariadb")),
    Service("PostgreSQL", DATASTORE, "HIGH", "MEDIUM",
            "As with any database port: reachable means attackable, and "
            "pg_hba configurations that trust a wide range are common.",
            "Bind to the application network, require scram-sha-256 and "
            "TLS, and firewall 5432.",
            ports=(5432,), aliases=("postgresql", "postgres")),
    Service("Microsoft SQL Server", DATASTORE, "HIGH", "MEDIUM",
            "Exposed MSSQL is a credential-stuffing target, and xp_cmdshell "
            "turns a database login into command execution where it is "
            "enabled.",
            "Keep 1433 and the 1434 browser service off public networks, "
            "require encryption, and disable xp_cmdshell.",
            ports=(1433, 1434), aliases=("ms-sql-s", "ms-sql-m", "mssql")),
    Service("Oracle Database", DATASTORE, "HIGH", "MEDIUM",
            "The TNS listener discloses version and service names before "
            "authentication and has a long history of pre-auth flaws.",
            "Restrict by address, set a listener password, and keep 1521 "
            "internal.",
            ports=(1521, 1522), aliases=("oracle", "oracle-tns", "ncube-lm")),
    Service("CouchDB", DATASTORE, "CRITICAL", "HIGH",
            "CouchDB's HTTP API has had unauthenticated-admin flaws, and "
            "an exposed instance typically allows database enumeration.",
            "Require authentication, bind internally, firewall 5984.",
            ports=(5984, 6984), aliases=("couchdb",)),
    Service("Cassandra", DATASTORE, "HIGH", "MEDIUM",
            "Cassandra's default configuration uses the AllowAllAuthenticator "
            "— no authentication of any kind.",
            "Enable PasswordAuthenticator, require TLS, firewall 9042 and "
            "7000.",
            ports=(9042, 7000, 7001, 9160), aliases=("cassandra", "apani1")),
    Service("etcd", ORCHESTRATION, "CRITICAL", "HIGH",
            "etcd holds a Kubernetes cluster's entire state, service "
            "account tokens included. Read access to etcd is read access "
            "to every secret in the cluster.",
            "Require client certificates, bind to the control plane "
            "network, and never expose 2379.",
            dangerous_anywhere=True, ports=(2379, 2380), aliases=("etcd",)),
    Service("Riak / Zookeeper / Consul", DATASTORE, "HIGH", "MEDIUM",
            "Coordination and configuration stores typically ship without "
            "authentication and hold the keys to the services that use "
            "them.",
            "Enable ACLs and TLS, and restrict to the cluster network.",
            ports=(2181, 8098, 8500, 8501),
            aliases=("zookeeper", "riak", "consul", "eforward")),

    # ── container and orchestration APIs ────────────────────────────
    Service("Docker API", ORCHESTRATION, "CRITICAL", "CRITICAL",
            "An exposed Docker daemon socket is root on the host, by "
            "design: anyone who can reach it can start a privileged "
            "container that mounts the host filesystem. 2375 is "
            "unauthenticated and unencrypted.",
            "Never expose the daemon over TCP. If remote access is "
            "required, use TLS client certificates on 2376 and restrict "
            "by address.",
            dangerous_anywhere=True, ports=(2375, 2376),
            aliases=("docker", "docker-s")),
    Service("Kubernetes API server", ORCHESTRATION, "HIGH", "MEDIUM",
            "The API server is the cluster's control plane. Exposure "
            "matters because anonymous access is sometimes still bound to "
            "a role, and because it is a precise target for credential "
            "theft.",
            "Restrict by address or put it behind a bastion, disable "
            "anonymous auth, and audit RBAC.",
            ports=(6443, 8443), aliases=("kubernetes", "sun-sr-https")),
    Service("Kubelet API", ORCHESTRATION, "CRITICAL", "HIGH",
            "The read-write kubelet port allows running commands in any "
            "pod on the node when anonymous authentication is enabled, "
            "which was the default for years.",
            "Set --anonymous-auth=false and --authorization-mode=Webhook, "
            "and keep 10250 off any routable network.",
            dangerous_anywhere=True, ports=(10250, 10255),
            aliases=("kubelet",)),

    # ── management consoles and CI ──────────────────────────────────
    Service("Jenkins", ADMIN_SERVICE, "CRITICAL", "HIGH",
            "Jenkins executes code by definition. An exposed instance "
            "with signup enabled, anonymous read, or an unpatched plugin "
            "is a direct route to code execution and to every credential "
            "the pipelines hold.",
            "Put it behind SSO and a VPN, disable anonymous access, and "
            "keep plugins current.",
            ports=(8080, 8081, 50000), aliases=("jenkins",)),
    Service("Management or admin interface", ADMIN_SERVICE, "HIGH", "LOW",
            "An administrative interface reachable from the internet is "
            "an authentication surface for the thing it administers, and "
            "default credentials on these are common.",
            "Restrict to a management network or VPN and require MFA.",
            ports=(8834, 9000, 10000, 4848, 7001, 8161, 15672, 5601, 3000,
                   9090, 8200),
            aliases=("webmin", "portainer", "glassfish", "weblogic",
                     "activemq", "rabbitmq", "kibana", "grafana",
                     "prometheus", "vault", "nessus", "zeus-admin",
                     "teradataordbms")),
    Service("Printer / JetDirect", OTHER, "MEDIUM", "LOW",
            "Raw printing ports accept jobs without authentication, and "
            "the embedded web servers on printers hold address books and "
            "sometimes domain credentials for scan-to-folder.",
            "Keep printers off public networks and change their admin "
            "credentials.",
            ports=(515, 631, 9100), aliases=("printer", "ipp", "jetdirect",
                                             "hp-pdl-datastr")),

    # ── mail, directory, DNS ────────────────────────────────────────
    Service("SMTP", MAIL, "MEDIUM", "LOW",
            "An exposed SMTP service is worth testing for open relay and "
            "for user enumeration through VRFY and RCPT responses, and it "
            "discloses its software in the banner.",
            "Require authentication for submission, disable VRFY/EXPN, "
            "and confirm the server is not an open relay.",
            ports=(25, 465, 587, 2525), aliases=("smtp", "smtps",
                                                 "submission")),
    Service("LDAP", DIRECTORY, "HIGH", "MEDIUM",
            "An exposed directory service often permits anonymous bind, "
            "which hands over the organisation's user list, group "
            "membership and sometimes more.",
            "Disable anonymous bind, require LDAPS, and restrict to the "
            "hosts that need it.",
            ports=(389, 636, 3268, 3269), aliases=("ldap", "ldapssl",
                                                   "globalcatLDAP")),
    Service("Kerberos", DIRECTORY, "MEDIUM", "LOW",
            "An exposed KDC allows username enumeration and offline "
            "attacks on pre-authentication data (AS-REP roasting) against "
            "accounts that do not require pre-auth.",
            "Keep 88 off public networks and require pre-authentication "
            "on every account.",
            ports=(88, 464), aliases=("kerberos-sec", "kpasswd5")),
    Service("DNS", OTHER, "MEDIUM", "LOW",
            "A DNS service answering from outside is worth checking for "
            "zone transfer, which hands over the internal name space, and "
            "for recursion, which makes it an amplifier.",
            "Restrict zone transfers to the secondaries, disable "
            "recursion for the internet, and rate-limit responses.",
            ports=(53,), aliases=("domain", "dns")),

    # ── brokers and queues ──────────────────────────────────────────
    Service("Message broker", BROKER, "HIGH", "MEDIUM",
            "Brokers carry application messages and frequently ship with "
            "guest credentials or none. Kafka's default configuration has "
            "no authentication at all.",
            "Require authentication and TLS, and restrict to the "
            "application network.",
            ports=(1883, 5672, 8883, 9092, 61613, 61616),
            aliases=("mqtt", "amqp", "kafka", "stomp", "activemq-broker")),

    # ── the expected ones ───────────────────────────────────────────
    Service("HTTP", WEB, "INFO", "INFO",
            "A web service, which is what the rest of this scan is "
            "about. Recorded so the port inventory is complete.",
            "", ports=(80, 8000, 8080, 8888),
            aliases=("http", "http-alt", "http-proxy", "https", "ssl/http",
                     "https-alt", "ssl/https")),
)

_BY_PORT = {}
_BY_ALIAS = {}
for _service in SERVICES:
    for _port in _service.ports:
        _BY_PORT.setdefault(_port, _service)
    for _alias in _service.aliases:
        _BY_ALIAS.setdefault(_alias.lower(), _service)


@dataclass
class Assessment:
    """What one open port amounts to."""

    port: int
    protocol: str
    service_name: str          # what nmap called it
    version: str               # the version string nmap returned, if any
    entry: Service = None      # the table entry, when one matched
    public: bool = None        # None when reachability is unknown
    severity: str = "INFO"
    issue_key: str = OTHER
    title: str = ""
    why: str = ""
    fix: str = ""
    notes: list = field(default_factory=list)

    @property
    def has_version(self):
        """Did the service actually disclose a VERSION?

        Not "did nmap print anything in that column". nmap writes
        "http" or "ssl/http" or a product name with no release in it,
        and a finding titled "Service version disclosed" whose evidence
        contains no version is a finding that contradicts itself —
        which is exactly what it did on ports 80 and 443.
        """
        return bool(version_token(self.version))


#: A release number: at least two dot-separated numeric parts, or one
#: number with a suffix the way OpenSSH writes 8.9p1. A bare "2" in a
#: banner is not a version, and "(Ubuntu)" is not either.
_VERSION = re.compile(r"\b\d+\.\d+(?:\.\d+)*[A-Za-z]?\d*\b|\b\d+\.\d+p\d+\b")

#: Things nmap puts in the version column that are NOT versions. These
#: are tunnel and protocol notes, which is why "ssl/http" and a bare
#: "http" were producing version-disclosure findings with no version in
#: them.
NOT_A_VERSION = frozenset({
    "http", "https", "ssl", "ssl/http", "ssl/https", "tcpwrapped",
    "http-proxy", "http-alt", "unknown", "filtered", "generic",
})


def version_token(banner):
    """The release number in a banner, or "" when there is not one."""
    text = str(banner or "").strip()
    if not text or text.lower() in NOT_A_VERSION:
        return ""
    match = _VERSION.search(text)
    return match.group(0) if match else ""


def lookup(port, service_name=""):
    """The table entry for this port or nmap service name, or None.

    The NAME is tried first. nmap's own service detection is better
    evidence than the port number — a Redis instance on 8080 is Redis,
    and an nginx on 2375 is not the Docker API.
    """
    name = str(service_name or "").strip().lower()
    for candidate in (name, name.split("/")[-1], name.split("?")[0]):
        if candidate and candidate in _BY_ALIAS:
            return _BY_ALIAS[candidate]
    try:
        return _BY_PORT.get(int(port))
    except Exception:                                       # noqa: BLE001
        return None


def is_public_address(value):
    """True when this address is routable from the internet.

    ``None`` when it cannot be decided — a hostname that did not
    resolve, or no address at all. A finding built on an unknown answer
    says so rather than assuming the worse or the better case.
    """
    text = str(value or "").strip()
    if not text:
        return None
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if address.is_private or address.is_loopback or address.is_link_local \
            or address.is_reserved or address.is_multicast:
        return False
    return True


def assess(port, protocol="tcp", service_name="", version="", public=None):
    """What to report for one open port."""
    entry = lookup(port, service_name)
    result = Assessment(
        port=int(port), protocol=str(protocol or "tcp"),
        service_name=str(service_name or ""), version=str(version or ""),
        entry=entry, public=public)

    if entry is None:
        result.severity = "INFO"
        result.issue_key = OTHER
        result.title = (f"Service on {port}/{result.protocol} "
                        f"({service_name or 'unidentified'})")
        result.why = (
            "This port is open and this scan does not recognise the "
            "service on it. Recorded so the inventory is complete; what "
            "it is, and whether it belongs here, is a question for "
            "whoever owns the host.")
        return result

    result.issue_key = entry.category
    if entry.dangerous_anywhere:
        result.severity = entry.public
        if public is False:
            result.severity = max_severity(entry.internal, entry.public) \
                if entry.dangerous_anywhere else entry.internal
    elif public is True:
        result.severity = entry.public
    elif public is False:
        result.severity = entry.internal
    else:
        # Reachability unknown. Rate it as internal — the lower of the
        # two — and say that is what was assumed, rather than inflating
        # a finding on an assumption the reader cannot see.
        result.severity = entry.internal
        result.notes.append(
            "The address of this host could not be classified as public "
            "or internal, so this is rated as an internal exposure. If "
            "this host is reachable from the internet, the rating for "
            f"this service is {entry.public}.")

    where = ("reachable from the internet" if public is True
             else "open" if public is None else "open internally")
    result.title = f"{entry.name} {where} on {port}/{result.protocol}"
    result.why = entry.why
    result.fix = entry.fix
    if entry.dangerous_anywhere and public is not True:
        result.notes.append(
            "This service is rated the same wherever it runs: the "
            "weakness is in the protocol, not in where it is reachable "
            "from.")
    return result


_ORDER = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def max_severity(*values):
    best = "INFO"
    for value in values:
        if str(value).upper() in _ORDER and \
                _ORDER.index(str(value).upper()) > _ORDER.index(best):
            best = str(value).upper()
    return best


#: Categories whose rating rests on the service being what nmap says it
#: is, where nmap is often guessing from the port number alone. "Jenkins
#: reachable from the internet on 8080" at CRITICAL, from nothing but an
#: open 8080, is a finding that has to be withdrawn in front of a
#: client. These need a probe before they are stated as fact.
NEEDS_CONFIRMATION = frozenset({
    ADMIN_SERVICE, MANAGEMENT, ORCHESTRATION, BROKER, MONITORING,
})

#: What an unconfirmed finding in those categories is capped at. The
#: port IS open, which is worth saying; what is listening on it is not
#: established, so it cannot carry the rating of the worst thing it
#: might be.
UNCONFIRMED_CEILING = "MEDIUM"


def needs_confirmation(assessment):
    """Must this finding be probed before it is reported as fact?"""
    if assessment is None or assessment.entry is None:
        return False
    if assessment.entry.category not in NEEDS_CONFIRMATION:
        return False
    # A version banner means nmap read a response and parsed it, which
    # is evidence of what the service is. A bare service name from the
    # port number is not.
    return not version_token(assessment.version)


def cap_unconfirmed(severity):
    """The rating an unconfirmed service identification may carry."""
    order = list(_ORDER)
    if str(severity).upper() not in order:
        return severity
    if order.index(str(severity).upper()) > order.index(UNCONFIRMED_CEILING):
        return UNCONFIRMED_CEILING
    return str(severity).upper()


#: Products whose version string in an nmap banner is worth checking
#: against the version catalogue. The catalogue's own PRODUCTS table
#: decides what can actually be looked up; this is the mapping from what
#: a banner says to what the catalogue calls it.
BANNER_PRODUCTS = (
    (re.compile(r"\bOpenSSH[ /]+([0-9][0-9.p]*)", re.I), "openssh"),
    (re.compile(r"\bnginx[ /]+([0-9][0-9.]*)", re.I), "nginx"),
    (re.compile(r"\bApache(?:/| )httpd[ /]+([0-9][0-9.]*)", re.I), "apache"),
    (re.compile(r"\bApache Tomcat[ /]+([0-9][0-9.]*)", re.I), "tomcat"),
    (re.compile(r"\bMicrosoft IIS httpd[ /]+([0-9][0-9.]*)", re.I), "iis"),
    (re.compile(r"\bMySQL[ /]+([0-9][0-9.]*)", re.I), "mysql"),
    (re.compile(r"\bMariaDB[ /]+([0-9][0-9.]*)", re.I), "mariadb"),
    (re.compile(r"\bPostgreSQL[ /]+([0-9][0-9.]*)", re.I), "postgresql"),
    (re.compile(r"\bProFTPD[ /]+([0-9][0-9.]*)", re.I), "proftpd"),
    (re.compile(r"\bvsftpd[ /]+([0-9][0-9.]*)", re.I), "vsftpd"),
    (re.compile(r"\bPostfix", re.I), "postfix"),
    (re.compile(r"\bExim smtpd[ /]+([0-9][0-9.]*)", re.I), "exim"),
    (re.compile(r"\bDovecot", re.I), "dovecot"),
    (re.compile(r"\bISC BIND[ /]+([0-9][0-9.]*)", re.I), "bind"),
    (re.compile(r"\bRedis key-value store[ /]+([0-9][0-9.]*)", re.I),
     "redis"),
    (re.compile(r"\bMongoDB[ /]+([0-9][0-9.]*)", re.I), "mongodb"),
    (re.compile(r"\bPHP[ /]+([0-9][0-9.]*)", re.I), "php"),
    (re.compile(r"\bOpenSSL[ /]+([0-9][0-9.a-z]*)", re.I), "openssl"),
)


def product_in_banner(banner):
    """``(product, version)`` named by an nmap version string, or ("", "")."""
    text = str(banner or "")
    for pattern, product in BANNER_PRODUCTS:
        match = pattern.search(text)
        if match:
            version = match.group(1) if match.groups() else ""
            return product, (version or "").strip()
    return "", ""
