"""ПР. Аудит учётных записей и прав доступа."""

import sys
from datetime import date

from iam import effective_permissions, new_hires
from store import compare, load_json, read_csv, today


def enabled(account):
    """Учётная запись включена, если поле disabled_at пустое."""
    return account["disabled_at"] == ""


def active_accounts(employees, accounts):
    """Пары (учётная запись, сотрудник) для включённых учётных записей
    сотрудников со статусом active. Используйте в заданиях 4.3-4.5."""
    active = {e["emp_id"]: e for e in employees if e["status"] == "active"}
    return [
        (a, active[a["emp_id"]])
        for a in accounts
        if enabled(a) and a["emp_id"] in active
    ]


def fired_enabled(employees, accounts):
    """Пример готовой проверки: включённые учётные записи уволенных сотрудников."""
    fired = {e["emp_id"] for e in employees if e["status"] == "fired"}
    return [a["login"] for a in accounts if enabled(a) and a["emp_id"] in fired]


def orphans(employees, accounts):
    """Задание 4.2. Логины включённых учётных записей, у которых emp_id пустой
    или такого emp_id нет в hr.csv."""
    known = {e["emp_id"] for e in employees}
    return [
        a["login"] for a in accounts
        if enabled(a) and (a["emp_id"] == "" or a["emp_id"] not in known)
    ]


def inactive(employees, accounts, today_, days):
    """Задание 4.3. Логины из active_accounts(), у которых last_login не пустой
    и с даты last_login до today_ прошло БОЛЬШЕ days дней
    (ровно days дней - не нарушение)."""
    result = []
    for a, _ in active_accounts(employees, accounts):
        if a["last_login"] == "":
            continue
        if (today_ - date.fromisoformat(a["last_login"])).days > days:
            result.append(a["login"])
    return result


def excess_rights(employees, accounts, grants, roles):
    """Задание 4.4. Список пар (login, permission) для учётных записей из
    active_accounts(): права из grants.csv, которых нет в effective_permissions()
    должности сотрудника."""
    allowed = {
        a["login"]: set(effective_permissions(e["position"], roles))
        for a, e in active_accounts(employees, accounts)
    }
    return [
        (g["login"], g["permission"])
        for g in grants
        if g["login"] in allowed and g["permission"] not in allowed[g["login"]]
    ]


def sod_conflicts(employees, accounts, grants, roles):
    """Задание 4.5. Список троек (login, право1, право2) для учётных записей из
    active_accounts(): у сотрудника в grants.csv есть ОБА права из пары
    roles["sod_conflicts"]."""
    result = []
    for a, _ in active_accounts(employees, accounts):
        have = {g["permission"] for g in grants if g["login"] == a["login"]}
        for p1, p2 in roles["sod_conflicts"]:
            if p1 in have and p2 in have:
                result.append((a["login"], p1, p2))
    return result


def run_audit():
    cfg, roles = load_json("config.json"), load_json("roles.json")
    emp, acc, gr = read_csv("hr.csv"), read_csv("accounts.csv"), read_csv("grants.csv")
    days = cfg["inactive_days"]
    return {
        "Новые сотрудники без учётной записи": len(new_hires(emp, acc)),
        "Уволенные с активной учётной записью": len(fired_enabled(emp, acc)),
        "Учётные записи без сотрудника": len(orphans(emp, acc)),
        f"Неактивные более {days} дней": len(inactive(emp, acc, today(), days)),
        "Лишние права (пар логин-право)": len(excess_rights(emp, acc, gr, roles)),
        "Сотрудники с конфликтом SoD": len(
            {c[0] for c in sod_conflicts(emp, acc, gr, roles)}
        ),
    }


if __name__ == "__main__":
    # python audit.py              - сравнение с контрольными значениями (зад. 4)
    # python audit.py --after-fix  - после исправлений все значения = 0 (зад. 5)
    compare(run_audit(), after_fix="--after-fix" in sys.argv)
