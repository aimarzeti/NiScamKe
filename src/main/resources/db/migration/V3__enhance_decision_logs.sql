alter table decision_logs add column if not exists threat_type varchar(64);
alter table decision_logs add column if not exists ai_explanation varchar(1200);
alter table decision_logs add column if not exists score_breakdown varchar(4000);

create index if not exists idx_decision_threat_type on decision_logs(threat_type);
