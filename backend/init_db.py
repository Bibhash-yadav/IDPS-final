
from app.database import Base, engine
from app.models import User, SecurityEvent, SecurityRule


def initialize_database():
    Base.metadata.create_all(bind=engine)
    print("IDPS database tables initialized successfully.")


if __name__ == "__main__":
    initialize_database()
