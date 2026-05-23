create table if not exists scam_registry (
  id bigserial primary key,
  domain_name varchar(255) not null unique,
  scam_type varchar(64) not null,
  threat_level varchar(32) not null,
  description varchar(1000) not null,
  flagged_at timestamp not null,
  reported_by varchar(255) not null,
  reported_at timestamp not null
);

create index if not exists idx_domain_name on scam_registry(domain_name);

create table if not exists decision_logs (
  id bigserial primary key,
  public_id varchar(36) not null unique,
  url varchar(1200) not null,
  domain_name varchar(255) not null,
  decision varchar(16) not null,
  risk_score int not null,
  confidence double precision not null,
  reason varchar(1000) not null,
  evidence_sources varchar(255) not null,
  created_at timestamp not null
);

create index if not exists idx_decision_public_id on decision_logs(public_id);
create index if not exists idx_decision_domain on decision_logs(domain_name);
create index if not exists idx_decision_created_at on decision_logs(created_at);

create table if not exists user_reports (
  id bigserial primary key,
  url varchar(1200) not null,
  domain_name varchar(255) not null,
  reporter_email varchar(255),
  scam_type varchar(64) not null,
  description varchar(1000),
  status varchar(32) not null default 'PENDING_REVIEW',
  created_at timestamp not null default now()
);

create index if not exists idx_user_reports_domain on user_reports(domain_name);
create index if not exists idx_user_reports_status on user_reports(status);