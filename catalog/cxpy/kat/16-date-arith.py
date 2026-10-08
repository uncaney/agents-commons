from datetime import date, datetime, timedelta, timezone
a, b = date(2026, 1, 1), date(2026, 4, 15)
days = (b - a).days
print(days, days // 7, days % 7, b - a)
for i in range(7):
    day = a + timedelta(days=i)
    print(day.isoformat(), day.strftime("%a"))
print(a + timedelta(days=90), (date(2026, 2, 1) - timedelta(days=1)).day, (date(2024, 3, 1) - timedelta(days=1)).day)
t = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(hours=36, minutes=90)
print(t.isoformat(), timedelta(days=1, seconds=3661), str(timedelta(hours=49)), timedelta(hours=1) * 2.5)
from datetime import date as _d
d2 = datetime(2026, 1, 1, 12, 30, 45, 123000, tzinfo=timezone.utc)
print(d2.isoweekday(), datetime.fromisoformat("2026-03-01T00:00:00+00:00").timestamp(), _d(2026, 1, 1).isocalendar(), _d.fromordinal(739617), d2.date(), d2.time(), d2.astimezone(timezone(timedelta(hours=2))).hour)
print(datetime.strptime("15/01/2026 08:05", "%d/%m/%Y %H:%M").isoformat(), d2.replace(year=2027).year, d2.utcoffset())
