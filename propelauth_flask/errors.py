class _UnauthorizedException(Exception):
    def __init__(self, message):
        self.message = message


class _UnexpectedException(Exception):
    def __init__(self, message):
        self.message = message


class _ForbiddenException(Exception):
    def __init__(self, message):
        self.message = message
