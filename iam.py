"""ПР. Учётные записи: логины, пароли, ролевая модель."""

import secrets
import string

from store import load_json, log_action, read_csv, today, write_csv

TRANSLIT = {
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e", "ж": "zh",
    "з": "z", "и": "i", "й": "y", "к": "k", "л": "l", "м": "m", "н": "n", "о": "o",
    "п": "p", "р": "r", "с": "s", "т": "t", "у": "u", "ф": "f", "х": "kh", "ц": "ts",
    "ч": "ch", "ш": "sh", "щ": "shch", "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu",
    "я": "ya", "ә": "a", "ғ": "g", "қ": "k", "ң": "n", "ө": "o", "ұ": "u", "ү": "u",
    "һ": "h", "і": "i",
}

COMMON_PASSWORDS = {
    "password", "qwerty", "123456", "12345678", "admin",
    "welcome", "p@ssw0rd", "qwerty123", "iloveyou", "1q2w3e4r",
}


def translit(text):
    """Задание 1. Переводит текст в латиницу по таблице TRANSLIT.
    Сначала текст переводится в нижний регистр. Латинские буквы a-z и цифры
    остаются как есть, все остальные символы (пробел, дефис, точка) удаляются.
    Примеры: translit("Шәріпов") -> "sharipov"; translit("Ким-Ли") -> "kimli"."""
    result = ""
    for ch in text.lower():
        if ch in TRANSLIT:
            result += TRANSLIT[ch]
        elif ch in string.ascii_lowercase or ch in string.digits:
            result += ch
        # всё остальное (пробел, дефис, точка и т. п.) пропускаем
    return result


def make_login(fullname, existing):
    """Задание 1. fullname - "Фамилия Имя". existing - множество занятых логинов.
    Логин = транслит первой буквы имени + "." + транслит фамилии.
    Если логин занят, добавить в конец 2, затем 3 и т. д.: a.serikov2, a.serikov3.
    Примеры: make_login("Нұрланова Дана", set()) -> "d.nurlanova"
             make_login("Сериков Арман", {"a.serikov"}) -> "a.serikov2"
    """
    surname, name = fullname.split()[:2]
    base = translit(name[0]) + "." + translit(surname)
    login = base
    n = 2
    while login in existing:
        login = f"{base}{n}"
        n += 1
    return login


def new_hires(employees, accounts):
    """Задание 1. Сотрудники (строки hr.csv) со статусом active,
    у которых нет ни одной учётной записи (их emp_id нет в accounts.csv)."""
    with_account = {a["emp_id"] for a in accounts}
    return [
        e for e in employees
        if e["status"] == "active" and e["emp_id"] not in with_account
    ]


def check_password(password, login, policy):
    """Задание 2. Возвращает список кодов нарушений строго в таком порядке:
    "LENGTH" - длина меньше policy["min_length"];
    "CLASSES" - классов символов меньше policy["min_classes"]. Классы: строчные
                буквы, заглавные буквы, цифры, прочие символы (4 класса);
    "LOGIN" - пароль содержит фамилию из логина (часть после точки без цифр
              в конце, если в ней 3 и более символа), без учёта регистра;
    "COMMON" - пароль (без учёта регистра) есть в COMMON_PASSWORDS.
    Пустой список [] - пароль подходит."""
    raise NotImplementedError


def generate_password(policy):
    """Задание 2. Случайный пароль длиной max(policy["min_length"], 12),
    в котором есть все 4 класса символов. Использовать только модуль secrets."""
    raise NotImplementedError


def effective_permissions(position, roles):
    """Задание 3. Отсортированный список прав должности (без повторов):
    объединение прав всех ролей должности. roles - содержимое roles.json.
    Пример: effective_permissions("manager", roles) ->
            ["crm.edit", "crm.read", "mail.use", "portal.read"]"""
    raise NotImplementedError


def write_role_matrix(roles, path="role_matrix.csv"):
    """Задание 3. CSV-матрица: строки - должности (в порядке roles.json),
    столбцы - все права по алфавиту, в ячейке "+" если право есть, иначе пусто.
    Первая строка: position,<право1>,<право2>,..."""
    raise NotImplementedError


def create_account(emp, accounts, grants, roles, policy):
    """Задание 3. Создаёт учётную запись сотрудника emp (строка hr.csv):
    1) логин - make_login() с учётом всех существующих логинов;
    2) пароль - generate_password();
    3) добавить в accounts строку: login, emp_id, created = today().isoformat(),
       last_login = "", disabled_at = "";
    4) добавить в grants по строке на каждое право из effective_permissions();
    5) log_action("create", login, "<ФИО>, <должность>").
    Возвращает (login, password). Пароль никуда не записывается."""
    raise NotImplementedError


if __name__ == "__main__":
    cfg, roles = load_json("config.json"), load_json("roles.json")
    employees, accounts, grants = (
        read_csv("hr.csv"),
        read_csv("accounts.csv"),
        read_csv("grants.csv"),
    )
    write_role_matrix(roles)
    for emp in new_hires(employees, accounts):
        login, pw = create_account(emp, accounts, grants, roles, cfg["password_policy"])
        print(f"{emp['emp_id']} {emp['fullname']:<25} {login:<16} {pw}")
    write_csv("accounts.csv", accounts)
    write_csv("grants.csv", grants)
