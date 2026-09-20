
import random
import string

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

PASSWORDS = [
    "UserPass1!", "temp", "Cyber$ecur1ty", "guest", "P0w3rful@Pass",
    "login", "Defens3#2023", "abc123", "Elit3@Secur", "demo",
]
CRITERIA = {
    "min_length": 9,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}
FORBIDDEN_PASSWORDS = {"temp", "guest", "login", "demo", "abc123", "user"}

REUSED_COUNT = 3
EXTRA_LENGTH = 4

LEVEL_FORBIDDEN = "Заборонений"
LEVEL_WEAK = "Слабкий"
LEVEL_MEDIUM = "Середній"
LEVEL_STRONG = "Сильний"
LEVEL_VERY_STRONG = "Дуже сильний"


def add_reused_passwords(passwords, count=REUSED_COUNT):

    result = list(passwords)
    indexes = random.sample(range(len(passwords)), count)
    for index in indexes:
        result.append(passwords[index])
    return result, indexes


def has_special(password):

    return any(char in string.punctuation for char in password)


def analyze_password(password, all_passwords, criteria, forbidden):

    min_length = criteria["min_length"]
    if password.lower() in forbidden or len(password) < min_length:
        return LEVEL_FORBIDDEN

    checks = []
    if criteria["require_digits"]:
        checks.append(any(char.isdigit() for char in password))
    if criteria["require_upper"]:
        checks.append(any(char.isupper() for char in password))
    if criteria["require_special"]:
        checks.append(has_special(password))

    met = sum(checks)
    if met == len(checks):
        is_long = len(password) >= min_length + EXTRA_LENGTH
        is_unique = all_passwords.count(password) == 1
        if is_long and is_unique:
            return LEVEL_VERY_STRONG
        return LEVEL_STRONG
    if met >= 2:
        return LEVEL_MEDIUM
    return LEVEL_WEAK


def print_report(passwords, criteria, forbidden):

    print(f"{'№':<4}{'Пароль':<22}{'Довжина':<10}{'Рівень'}")
    print("-" * 55)
    for number, password in enumerate(passwords, start=1):
        level = analyze_password(password, passwords, criteria, forbidden)
        print(f"{number:<4}{password:<22}{len(password):<10}{level}")


def main():

    print("Завдання 1: аналізатор надійності паролів")
    print(f"Студент: {STUDENT_NAME}")
    print(f"Група: {GROUP_NAME}, варіант: {VARIANT_NUMBER}\n")

    passwords, indexes = add_reused_passwords(PASSWORDS)
    print(f"Продубльовано паролі з індексами: {sorted(indexes)}\n")
    print_report(passwords, CRITERIA, FORBIDDEN_PASSWORDS)


if __name__ == "__main__":
    main()
