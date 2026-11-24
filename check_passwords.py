"""ПР. Задание 2. Проверка 1000 сгенерированных паролей."""

from iam import check_password, generate_password
from store import load_json

policy = load_json("config.json")["password_policy"]
N = 1000

passwords = [generate_password(policy) for _ in range(N)]
bad = [p for p in passwords if check_password(p, "x.test", policy)]

print("Политика варианта:", policy)
print("Пример пароля:", passwords[0])
print(f"Паролей с нарушениями: {len(bad)} из {N}")
