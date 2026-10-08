from datetime import datetime, date, timezone
d = datetime(2026, 1, 1, 12, 30, 45, 123000, tzinfo=timezone.utc)
print(d.isoformat(), int(d.timestamp()), d.weekday(), d.strftime('%Y-%m-%d %H:%M:%S %A %j'))
print(datetime.fromtimestamp(0, timezone.utc).isoformat(), date(2024, 2, 29).isoformat(), date(2026, 1, 1).isocalendar()[1])
