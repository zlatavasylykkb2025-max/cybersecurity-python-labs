"""Завдання 3: хешування, CSV-база та JSON-логування (варіант 3)."""

import csv
import functools
import hashlib
import hmac
import json
from datetime import datetime
from pathlib import Path

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

HASH_ALGORITHM = "sha1"
MIN_PASSWORD_LENGTH = 8
SALT = str(VARIANT_NUMBER).zfill(5)

DATA_DIR = Path(__file__).resolve().parent / "data"
USERS_FILE = DATA_DIR / "users.csv"
LOG_FILE = DATA_DIR / "log.json"

USERS_TO_REGISTER = (
    ("admin", "Adm1n#Secure"),
    ("alice", "Alice!Pass2026"),
    ("bob", "B0b$Strong99"),
    ("carol", "Carol@Cyber7"),
    ("dave", "D4ve#Network"),
    ("eve", "Ev3!Analyst"),
    ("frank", "Fr@nk2026Sec"),
    ("grace", "Gr4ce$Audit"),
    ("heidi", "H31di#Crypto"),
    ("ivan", "Iv@n2026Lab"),
)

# Список (логін, хеш), який заповнюється з CSV-файлу
users_db = []


class ValidationError(Exception):
    """Пароль не відповідає вимогам політики безпеки."""


def generate_hash(password: str, salt: str = "00000") -> str:
    """Повертає hex-хеш від конкатенації пароля та солі."""
    if not password or not salt:
        raise ValueError("Пароль і сіль не можуть бути порожніми.")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль коротший за {MIN_PASSWORD_LENGTH} символів."
        )

    data = (password + salt).encode("utf-8")
    return hashlib.new(HASH_ALGORITHM, data).hexdigest()


def create_user(username, password):
    """Повертає кортеж (логін, хеш пароля) з персональною сіллю."""
    return username, generate_hash(password, SALT)


def create_users(users_list):
    """Записує користувачів у users.csv у форматі логін,хеш.

    Повертає кількість записаних користувачів.
    """
    records = []

    for username, password in users_list:
        try:
            records.append(create_user(username, password))
        except (ValueError, ValidationError) as error:
            print(f"Пропущено користувача {username!r}: {error}")

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    with USERS_FILE.open("w", newline="", encoding="utf-8") as file:
        csv.writer(file).writerows(records)

    return len(records)


def load_users_db():
    """Зчитує users.csv у список users_db."""
    users_db.clear()

    with USERS_FILE.open("r", newline="", encoding="utf-8") as file:
        for row in csv.reader(file):
            if len(row) == 2:
                users_db.append((row[0], row[1]))

    return users_db


def print_users_table(records):
    """Виводить базу користувачів у вигляді таблиці."""
    print(
        f"{'№':<4}"
        f"{'Логін':<10}"
        f"{'Хеш пароля (' + HASH_ALGORITHM + ')'}"
    )
    print("-" * 58)

    for number, (username, hash_value) in enumerate(records, start=1):
        print(f"{number:<4}{username:<10}{hash_value}")


def write_log(entry):
    """Додає запис до log.json (журнал зберігається як JSON-масив)."""
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)

        try:
            with LOG_FILE.open("r", encoding="utf-8") as file:
                records = json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            records = []

        if not isinstance(records, list):
            records = []

        records.append(entry)

        with LOG_FILE.open("w", encoding="utf-8") as file:
            json.dump(
                records,
                file,
                ensure_ascii=False,
                indent=2,
            )

    except PermissionError:
        print("Помилка: немає прав для запису журналу подій.")
    except OSError as error:
        print(f"Помилка запису журналу подій: {error}")


def log_event(func):
    """Декоратор: журналює кожну спробу входу в log.json.

    Пароль у журнал не потрапляє: у args/kwargs записуються лише
    додаткові аргументи, передані понад логін і пароль.
    """

    @functools.wraps(func)
    def wrapper(username=None, password=None, *args, **kwargs):
        result = "failure"

        try:
            success = func(username, password, *args, **kwargs)
            result = "success" if success else "failure"
            return success

        finally:
            write_log(
                {
                    "event": "login",
                    "user": username,
                    "result": result,
                    "timestamp": datetime.now()
                    .astimezone()
                    .strftime("%Y-%m-%d %H:%M:%S"),
                    "args": list(args),
                    "kwargs": dict(kwargs),
                }
            )

    return wrapper


@log_event
def login(username: str, password: str) -> bool:
    """Перевіряє логін і пароль за базою users_db."""
    if not username or not password:
        raise ValueError("Логін і пароль не можуть бути порожніми.")

    try:
        candidate = generate_hash(password, SALT)
    except ValidationError:
        # Занадто короткий пароль не може збігтися з жодним хешем
        return False

    stored_hash = dict(users_db).get(username)

    if stored_hash is None:
        return False

    return hmac.compare_digest(stored_hash, candidate)


def try_login(username, password):
    """Виконує спробу входу та виводить результат без traceback."""
    try:
        ok = login(username, password)

    except ValueError as error:
        print(f"user={username!r} -> ПОМИЛКА ({error})")

    else:
        print(
            f"user={username!r} -> "
            f"{'SUCCESS' if ok else 'FAILURE'}"
        )


def main():
    """Реєструє користувачів, читає базу та демонструє автентифікацію."""
    print("=== Завдання 3: хешування, CSV та логування ===")
    print(f"Студент: {STUDENT_NAME}")
    print(f"Група: {GROUP_NAME}, варіант: {VARIANT_NUMBER}")
    print(
        f"Алгоритм: {HASH_ALGORITHM}, сіль: {SALT}, "
        f"мін. довжина: {MIN_PASSWORD_LENGTH}\n"
    )

    try:
        count = create_users(USERS_TO_REGISTER)

        print(
            f"Записано користувачів: {count} -> "
            f"{USERS_FILE.name}\n"
        )

        print_users_table(load_users_db())

    except FileNotFoundError:
        print("Помилка: файл або папку не знайдено.")
        return

    except PermissionError:
        print("Помилка: недостатньо прав доступу до файлу.")
        return

    except OSError as error:
        print(f"Помилка вводу-виводу: {error}")
        return

    except ValidationError as error:
        print(f"Помилка валідації: {error}")
        return

    except ValueError as error:
        print(f"Некоректні дані: {error}")
        return

    print("\nСпроби входу:")

    try_login("admin", "Adm1n#Secure")      # успіх
    try_login("alice", "WrongPass#123")     # невірний пароль
    try_login("nobody", "Whatever#123")     # користувача немає
    try_login("eve", "short")               # занадто короткий пароль
    try_login("bob", "")                    # порожній пароль
    try_login("", "B0b$Strong99")           # порожній логін

    print(f"\nЖурнал подій: {LOG_FILE.name}")


if __name__ == "__main__":
    main()