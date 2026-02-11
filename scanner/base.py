from abc import ABC, abstractmethod


class BaseScanner(ABC):
    """
    Abstract base scanner class.
    Concrete scanners (e.g., BOLAScanner) must implement scan().
    """

    @abstractmethod
    async def scan(self):
        """
        Execute scanner logic.
        Must return a list of findings.
        """
        raise NotImplementedError
