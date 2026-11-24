"""ПР. Анализ журнала входов auth_log.csv."""

from datetime import datetime, timedelta

from store import FMT, compare, load_json, read_csv


def bruteforce(log, attempts, minutes):
    """Задание 6.1. Отсортированный список IP-адресов, с которых было подряд
    attempts неудачных попыток (result = fail), и между первой и последней из
    них прошло НЕ БОЛЬШЕ minutes минут. Логин значения не имеет."""
    fails = {}
    for r in log:
        if r["result"] == "fail":
            fails.setdefault(r["ip"], []).append(datetime.strptime(r["time"], FMT))

    found = set()
    for ip, times in fails.items():
        times.sort()
        for i in range(len(times) - attempts + 1):
            if times[i + attempts - 1] - times[i] <= timedelta(minutes=minutes):
                found.add(ip)
                break
    return sorted(found)


def off_hours(log, start, end):
    """Задание 6.2. Успешные входы (result = success), час которых меньше start
    или больше либо равен end. Пример для 9-18: 08:59 и 18:00 - нерабочее время."""
    result = []
    for r in log:
        if r["result"] != "success":
            continue
        hour = datetime.strptime(r["time"], FMT).hour
        if hour < start or hour >= end:
            result.append(r)
    return result


def disabled_logins(log, accounts):
    """Задание 6.3. Успешные входы в учётные записи, у которых заполнено
    disabled_at, если дата входа >= disabled_at."""
    disabled = {a["login"]: a["disabled_at"] for a in accounts if a["disabled_at"]}
    result = []
    for r in log:
        if r["result"] == "success" and r["login"] in disabled:
            if r["time"][:10] >= disabled[r["login"]]:
                result.append(r)
    return result


if __name__ == "__main__":
    cfg, log, acc = (
        load_json("config.json"),
        read_csv("auth_log.csv"),
        read_csv("accounts.csv"),
    )
    bf = cfg["bruteforce"]
    compare(
        {
            "IP-адреса с подбором пароля": len(
                bruteforce(log, bf["attempts"], bf["minutes"])
            ),
            "Входы в нерабочее время": len(off_hours(log, *cfg["work_hours"])),
            "Входы в отключённые учётные записи": len(disabled_logins(log, acc)),
        }
    )
