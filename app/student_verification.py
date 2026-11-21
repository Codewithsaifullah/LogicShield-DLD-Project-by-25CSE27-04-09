
def verify_student(database, enrollment_number, card_department):
    """
    Verify enrollment number and department
    against the approved student registry.
    """

    enrollment_number = enrollment_number.strip().upper()
    card_department = card_department.strip().upper()

    department_map = {
        "COMPUTER SYSTEMS ENGINEERING": "CSE",
        "CSE": "CSE",
        "SOFTWARE ENGINEERING": "SW",
        "SW": "SW"
    }

    expected_suffix = department_map.get(card_department)

    if not expected_suffix:
        return False, "Department not recognized"

    if not enrollment_number.endswith("-" + expected_suffix):
        return False, "Enrollment and department do not match"

    student = database.execute(
        """
        SELECT *
        FROM student_registry
        WHERE enrollment_number = ?
          AND department = ?
          AND is_active = 1
          AND is_approved = 1
        """,
        (enrollment_number, card_department if card_department in (
            "COMPUTER SYSTEMS ENGINEERING",
            "SOFTWARE ENGINEERING"
        ) else (
            "COMPUTER SYSTEMS ENGINEERING"
            if expected_suffix == "CSE"
            else "SOFTWARE ENGINEERING"
        ))
    ).fetchone()

    if student is None:
        return False, "Student not found, inactive, or not approved"

    return True, "Student verified successfully"
