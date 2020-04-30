CREATE SCHEMA smevdata version '3.7';

CREATE TABLE Users (
    login VARCHAR(50) NOT NULL PRIMARY KEY,
    password VARCHAR(150),
    sid VARCHAR(50) NOT NULL,
    name VARCHAR(50),
    email VARCHAR(50),
    phone VARCHAR(50),
    organization VARCHAR(50),
    fax VARCHAR(50),
    isBlocked BIT
);

CREATE INDEX idx_Users_sid ON Users(sid);

-------------------------------------------------------------------

CREATE TABLE ServiceType (
  smevId VARCHAR(32) NOT NULL PRIMARY KEY,
  active BIT,
  requestTag VARCHAR(32) NOT NULL,
  responseTag VARCHAR(32) NOT NULL,
  name VARCHAR(512),
  namespaceURI VARCHAR(128),
  version VARCHAR(16),
  providerName VARCHAR(16),
  providerDomen VARCHAR(16),
  providerISName VARCHAR(128)
);

------------------------------------------------------------------------

CREATE SEQUENCE SmevMessage_id START with 1001;

CREATE TABLE SmevMessage (
  id INT NOT NULL DEFAULT NEXTVAL(SmevMessage_id) PRIMARY KEY,
  uuid VARCHAR(36),
  /** {option: [DRAFT, SAVED, SENT, QUEUED, RESPONDED_DEPRICATED, RECEIVED]} */
  status INT NOT NULL,
  xml_file VARCHAR(512),
  details VARCHAR(1024),
  service_type VARCHAR(32) FOREIGN KEY REFERENCES ServiceType(smevId) ON UPDATE CASCADE ON DELETE NO ACTION,
  /** {option: [REQUEST, RESPONSE]} */
  type VARCHAR(16) NOT NULL,
  message_id VARCHAR(36),
  original_message_id VARCHAR(36),
  initial_message_time_stamp DATETIME,
  last_update_time_stamp DATETIME,
  /** {option: [SUCCESS, ERROR]} */
  smev_status INT,
  smev_status_msg TEXT,
  xml TEXT,
  printed_form_xml TEXT,
  regen_printed_form BIT NOT NULL DEFAULT 0
);

CREATE INDEX idx_SM_service_type ON SmevMessage(service_type);

CREATE INDEX idx_SM_type ON SmevMessage(type);

CREATE INDEX idx_SM_uuid ON SmevMessage(uuid);

CREATE INDEX idx_SM_message_id ON SmevMessage(message_id);

CREATE INDEX idx_SM_org_msg_id ON SmevMessage(original_message_id);

------------------------------------------------------------------------

CREATE SEQUENCE SmevServiceMessage_id START with 1001;

CREATE TABLE SmevServiceMessage (
  id INT NOT NULL DEFAULT NEXTVAL(SmevServiceMessage_id) PRIMARY KEY,
  uuid VARCHAR(36),
  xml_file_request VARCHAR(512),
  xml_file_response VARCHAR(512),
  original_message_id VARCHAR(36), -- информация, на какой запрос пришёл ответ
  initial_message_time_stamp DATETIME, -- когда отправлен запрос
  last_update_time_stamp DATETIME, -- когда пришёл ответ
  /** {option: [SUCCESS, ERROR]} */
  smev_status INT,
  smev_status_msg TEXT
);

CREATE INDEX idx_SSM_uuid ON SmevServiceMessage(uuid);

CREATE INDEX idx_SSM_org_msg_id ON SmevServiceMessage(original_message_id);

--------------------------------------------------------------------------------

CREATE SEQUENCE SmevQueueLog_id START with 1001;

CREATE TABLE SmevQueueLog (
  id INT NOT NULL DEFAULT NEXTVAL(SmevQueueLog_id) PRIMARY KEY,
  uuid VARCHAR(36),
  smevAction VARCHAR(20), -- sendToSmev, getFromSmev
  requestTime DATETIME,
  responseTime DATETIME,
  objectId VARCHAR(36)
);

CREATE INDEX idx_SQL_uuid ON SmevQueueLog(uuid);

CREATE INDEX idx_SQL_org_msg_id ON SmevQueueLog(objectId);

CREATE INDEX idx_SQL_req_time ON SmevQueueLog(requestTime);

---------------------------------------------------------------------

CREATE TABLE Region (
	reg_code VARCHAR(3) NOT NULL PRIMARY KEY,
	reg_caption VARCHAR(80) NOT NULL
);

CREATE INDEX idx_Reg_caption ON Region(reg_caption);

----------------------------------------------------------------------

CREATE TABLE SnilsRejectionReason (
	rejectId VARCHAR(8) NOT NULL PRIMARY KEY,
	code VARCHAR(50) NOT NULL,
	description VARCHAR(250) NOT NULL
);

CREATE INDEX idx_srr_Code ON SnilsRejectionReason(code);
CREATE INDEX idx_srr_Descr ON SnilsRejectionReason(description);

----------------------------------------------------------------------

CREATE TABLE SrSpChRejectionReason (
	code VARCHAR(50) NOT NULL PRIMARY KEY,
	description VARCHAR(250) NOT NULL
);

CREATE INDEX idx_sscrr_Descr ON SrSpChRejectionReason(description);

----------------------------------------------------------------------

CREATE TABLE ZadolgKodObrabotki (
	kod VARCHAR(2) NOT NULL PRIMARY KEY,
	opisanie VARCHAR(250) NOT NULL
);

CREATE INDEX idx_Zad_Kod_Obr_Opis ON ZadolgKodObrabotki(opisanie);
