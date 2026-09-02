-- ---------------------------------------------------------------------------
-- RADIUS-Schema fuer Entwicklung, Tests und Evaluierung.
--
-- Diese Datei ist eine eigenstaendig verfasste, funktional gleichwertige
-- Nachbildung des rlm_sql-Schemas von FreeRADIUS 3.2.x (Spalten, Typen und
-- Indizes richten sich nach den Abfragen in queries.conf).
--
-- Fuer den Produktivbetrieb gilt die Spezifikation, Abschnitt 7: dort wird das
-- Schema aus der FreeRADIUS-Installation selbst verwendet
-- (raddb/mods-config/sql/main/mysql/schema.sql). Der Manager veraendert dieses
-- Schema nicht (Abschnitt 4.1).
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS radcheck (
  id            INT UNSIGNED NOT NULL AUTO_INCREMENT,
  username      VARCHAR(64)  NOT NULL DEFAULT '',
  attribute     VARCHAR(64)  NOT NULL DEFAULT '',
  op            CHAR(2)      NOT NULL DEFAULT '==',
  value         VARCHAR(253) NOT NULL DEFAULT '',
  PRIMARY KEY (id),
  KEY username (username(32))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS radreply (
  id            INT UNSIGNED NOT NULL AUTO_INCREMENT,
  username      VARCHAR(64)  NOT NULL DEFAULT '',
  attribute     VARCHAR(64)  NOT NULL DEFAULT '',
  op            CHAR(2)      NOT NULL DEFAULT '=',
  value         VARCHAR(253) NOT NULL DEFAULT '',
  PRIMARY KEY (id),
  KEY username (username(32))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS radgroupcheck (
  id            INT UNSIGNED NOT NULL AUTO_INCREMENT,
  groupname     VARCHAR(64)  NOT NULL DEFAULT '',
  attribute     VARCHAR(64)  NOT NULL DEFAULT '',
  op            CHAR(2)      NOT NULL DEFAULT '==',
  value         VARCHAR(253) NOT NULL DEFAULT '',
  PRIMARY KEY (id),
  KEY groupname (groupname(32))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS radgroupreply (
  id            INT UNSIGNED NOT NULL AUTO_INCREMENT,
  groupname     VARCHAR(64)  NOT NULL DEFAULT '',
  attribute     VARCHAR(64)  NOT NULL DEFAULT '',
  op            CHAR(2)      NOT NULL DEFAULT '=',
  value         VARCHAR(253) NOT NULL DEFAULT '',
  PRIMARY KEY (id),
  KEY groupname (groupname(32))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS radusergroup (
  id            INT UNSIGNED NOT NULL AUTO_INCREMENT,
  username      VARCHAR(64)  NOT NULL DEFAULT '',
  groupname     VARCHAR(64)  NOT NULL DEFAULT '',
  priority      INT(11)      NOT NULL DEFAULT 1,
  PRIMARY KEY (id),
  KEY username (username(32))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS radacct (
  radacctid             BIGINT(21) UNSIGNED NOT NULL AUTO_INCREMENT,
  acctsessionid         VARCHAR(64)  NOT NULL DEFAULT '',
  acctuniqueid          VARCHAR(32)  NOT NULL DEFAULT '',
  username              VARCHAR(64)  NOT NULL DEFAULT '',
  realm                 VARCHAR(64)  DEFAULT '',
  nasipaddress          VARCHAR(15)  NOT NULL DEFAULT '',
  nasportid             VARCHAR(32)  DEFAULT NULL,
  nasporttype           VARCHAR(32)  DEFAULT NULL,
  acctstarttime         DATETIME     NULL DEFAULT NULL,
  acctupdatetime        DATETIME     NULL DEFAULT NULL,
  acctstoptime          DATETIME     NULL DEFAULT NULL,
  acctinterval          INT(12)      DEFAULT NULL,
  acctsessiontime       INT(12) UNSIGNED DEFAULT NULL,
  acctauthentic         VARCHAR(32)  DEFAULT NULL,
  connectinfo_start     VARCHAR(128) DEFAULT NULL,
  connectinfo_stop      VARCHAR(128) DEFAULT NULL,
  acctinputoctets       BIGINT(20)   DEFAULT NULL,
  acctoutputoctets      BIGINT(20)   DEFAULT NULL,
  calledstationid       VARCHAR(50)  NOT NULL DEFAULT '',
  callingstationid      VARCHAR(50)  NOT NULL DEFAULT '',
  acctterminatecause    VARCHAR(32)  NOT NULL DEFAULT '',
  servicetype           VARCHAR(32)  DEFAULT NULL,
  framedprotocol        VARCHAR(32)  DEFAULT NULL,
  framedipaddress       VARCHAR(15)  NOT NULL DEFAULT '',
  framedipv6address     VARCHAR(45)  NOT NULL DEFAULT '',
  framedipv6prefix      VARCHAR(45)  NOT NULL DEFAULT '',
  framedinterfaceid     VARCHAR(44)  NOT NULL DEFAULT '',
  delegatedipv6prefix   VARCHAR(45)  NOT NULL DEFAULT '',
  class                 VARCHAR(64)  DEFAULT NULL,
  PRIMARY KEY (radacctid),
  UNIQUE KEY acctuniqueid (acctuniqueid),
  KEY username (username),
  KEY framedipaddress (framedipaddress),
  KEY acctsessionid (acctsessionid),
  KEY acctsessiontime (acctsessiontime),
  KEY acctstarttime (acctstarttime),
  KEY acctstoptime (acctstoptime),
  KEY nasipaddress (nasipaddress),
  KEY callingstationid (callingstationid),
  KEY class (class)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS radpostauth (
  id            BIGINT(21)  NOT NULL AUTO_INCREMENT,
  username      VARCHAR(64) NOT NULL DEFAULT '',
  pass          VARCHAR(64) NOT NULL DEFAULT '',
  reply         VARCHAR(32) NOT NULL DEFAULT '',
  authdate      TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
  class         VARCHAR(64) DEFAULT NULL,
  PRIMARY KEY (id),
  KEY username (username),
  KEY authdate (authdate),
  KEY class (class)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS nas (
  id            INT(10)      NOT NULL AUTO_INCREMENT,
  nasname       VARCHAR(128) NOT NULL,
  shortname     VARCHAR(32)  DEFAULT NULL,
  type          VARCHAR(30)  DEFAULT 'other',
  ports         INT(5)       DEFAULT NULL,
  secret        VARCHAR(60)  NOT NULL DEFAULT 'secret',
  server        VARCHAR(64)  DEFAULT NULL,
  community     VARCHAR(50)  DEFAULT NULL,
  description   VARCHAR(200) DEFAULT 'RADIUS Client',
  PRIMARY KEY (id),
  KEY nasname (nasname)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
