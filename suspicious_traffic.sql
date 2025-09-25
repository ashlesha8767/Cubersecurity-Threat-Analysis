DROP TABLE IF EXISTS suspicious_traffic;
CREATE TABLE suspicious_traffic (
    bytes_in BIGINT,
    bytes_out BIGINT,
    creation_time TIMESTAMP,
    end_time TIMESTAMP,
    src_ip VARCHAR(50),
    src_ip_country_code VARCHAR(10),
    protocol VARCHAR(10),
    response_code INT,
    dst_port INT,
    dst_ip VARCHAR(50),
    rule_names VARCHAR(100),
    observation_name VARCHAR(100),
    source_meta VARCHAR(100),
    source_name VARCHAR(100),
    time TIMESTAMP,
    detection_types VARCHAR(50)
);
Select * from suspicious_traffic;

-------TOP 5 COUNTRIES BY SUSPICIOUS INTERACTION---------------
SELECT src_ip_country_code, COUNT(*) as suspicious_count
FROM suspicious_traffic
WHERE detection_types = 'waf_rule'
GROUP BY src_ip_country_code
ORDER BY suspicious_count DESC LIMIT 5;

-------High-Volume Attacks by Bytes_in---------------
SELECT src_ip, src_ip_country_code, SUM(bytes_in) as total_bytes_in
FROM suspicious_traffic
WHERE detection_types = 'waf_rule'
GROUP BY src_ip, src_ip_country_code
ORDER BY total_bytes_in DESC LIMIT 10;

-------Most Targeted Ports---------------
SELECT dst_port, COUNT(*) as attack_count
FROM suspicious_traffic
WHERE detection_types = 'waf_rule'
GROUP BY dst_port
ORDER BY attack_count DESC;

-------Average Data Transfer per Session---------------
SELECT src_ip_country_code,
AVG(bytes_in) AS avg_bytes_in,
AVG(bytes_out) AS avg_bytes_out
FROM suspicious_traffic
WHERE detection_types = 'waf_rule'
GROUP BY src_ip_country_code
ORDER BY avg_bytes_in DESC;

-------Time-Based Attack Analysis (Hourly)--------------
SELECT EXTRACT(HOUR FROM creation_time) AS hour_of_day,
COUNT(*) AS total_threats
FROM suspicious_traffic
WHERE detection_types = 'waf_rule'
GROUP BY hour_of_day
ORDER BY hour_of_day;