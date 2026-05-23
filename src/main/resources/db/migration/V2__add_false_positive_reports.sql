create table if not exists false_positive_reports (
  id bigserial primary key,
  url varchar(1200) not null,
  domain_name varchar(255) not null,
  decision_id varchar(36),
  reporter_email varchar(255),
  reason varchar(1000) not null,
  status varchar(32) not null default 'PENDING_REVIEW',
  review_note varchar(1000),
  created_at timestamp not null default now(),
  reviewed_at timestamp
);

create index if not exists idx_false_positive_domain on false_positive_reports(domain_name);
create index if not exists idx_false_positive_status on false_positive_reports(status);
