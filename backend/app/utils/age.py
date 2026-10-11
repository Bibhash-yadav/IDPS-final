
from datetime import date


def calculate_age(date_of_birth: date | None) -> int | None:
    if date_of_birth is None:
        return None

    today = date.today()

    age = today.year - date_of_birth.year

    if (today.month, today.day) < (
        date_of_birth.month,
        date_of_birth.day,
    ):
        age -= 1

    return age
