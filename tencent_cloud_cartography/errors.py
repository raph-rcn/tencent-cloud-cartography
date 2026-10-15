"""Public errors carry codes, never provider responses or authentication material."""


class CollectionError(RuntimeError):
    def __init__(self, code, message="Collection failed"):
        self.code = code
        super().__init__(message)


class AuthenticationError(CollectionError):
    def __init__(self, code, provider=None):
        self.provider = provider
        super().__init__(code, "Authentication failed; see the profile authentication status")
