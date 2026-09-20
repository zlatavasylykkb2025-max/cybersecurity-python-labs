"""Завдання 2: багаторівнева система контролю доступу (варіант 3)."""

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

USERS = {
    "security_chief": {
        "role": "security_officer", "clearance": 4,
        "department": "Security", "active": True,
    },
    "network_admin": {
        "role": "network_admin", "clearance": 3,
        "department": "Network", "active": True,
    },
    "help_desk": {
        "role": "support", "clearance": 1,
        "department": "Support", "active": True,
    },
    "auditor_ext": {
        "role": "auditor", "clearance": 3,
        "department": "Audit", "active": True,
    },
    "temp_worker": {
        "role": "temporary", "clearance": 1,
        "department": "Temp", "active": False,
    },
}
RESOURCES = [
    ("incident_reports", 4), ("network_topology", 3), ("user_manual", 1),
    ("vulnerability_scans", 3), ("root_access", 4), ("help_tickets", 1),
    ("penetration_tests", 4), ("firewall_rules", 3),
    ("software_licenses", 2), ("faq_docs", 1),
]
SECURITY_LEVELS = ("Unrestricted", "Limited", "Sensitive", "Classified")
BLOCKED_USERS = {"temp_worker", "fired_employee", "compromised_acc"}


def print_resources(resources, security_levels):
    """Виводить ресурси, замінюючи числовий рівень текстовою назвою."""
    print("Ресурси системи:")
    for number, (name, level) in enumerate(resources, start=1):
        print(f"{number:>2}. {name:<22} {security_levels[level - 1]}")


def check_access(username, resource_level, users, blocked_users):
    """Повертає рішення щодо доступу: ALLOW або DENY з причиною."""
    if username not in users:
        return "DENY (User not found)"
    if username in blocked_users:
        return "DENY (User is blocked)"
    user = users[username]
    if not user["active"]:
        return "DENY (Account inactive)"
    if user["clearance"] >= resource_level:
        return "ALLOW"
    return "DENY (Insufficient clearance)"


def main():
    """Запускає перевірку доступу всіх користувачів до всіх ресурсів."""
    print("=== Завдання 2: система контролю доступу ===")
    print(f"Студент: {STUDENT_NAME}")
    print(f"Група: {GROUP_NAME}, варіант: {VARIANT_NUMBER}\n")

    print_resources(RESOURCES, SECURITY_LEVELS)

    # Крім користувачів системи перевіряємо заблокованих, яких у ній немає
    usernames = list(USERS) + sorted(BLOCKED_USERS.difference(USERS))

    print("\nРезультати перевірки доступу:")
    for username in usernames:
        for resource_name, level in RESOURCES:
            decision = check_access(username, level, USERS, BLOCKED_USERS)
            print(f"user={username} resource={resource_name} -> {decision}")


if __name__ == "__main__":
    main()
