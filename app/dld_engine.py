
def evaluate_access(A, P, S, M, R, E):

    ALLOW = (
        A and
        P and
        not R and
        (not S or M) and
        not E
    )

    BLOCK = not ALLOW

    ALERT = (
        not A or
        not P or
        R or
        E
    )

    return {
        "ALLOW": ALLOW,
        "BLOCK": BLOCK,
        "ALERT": ALERT
    }
