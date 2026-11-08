
from sqlalchemy import text
from app.database import engine

try:
    with engine.connect() as connection:
        print("\n--- BACKEND DATABASE CONNECTION ---")

        result = connection.execute(text("""
            SELECT
                current_database() AS database_name,
                current_schema() AS schema_name,
                current_setting('search_path') AS search_path;
        """))

        print(result.mappings().all())

        print("\n--- USERS TABLE COLUMNS ---")

        result = connection.execute(text("""
            SELECT table_schema, column_name, data_type
            FROM information_schema.columns
            WHERE table_name = 'users'
            ORDER BY table_schema, ordinal_position;
        """))

        for row in result.mappings():
            print(dict(row))

except Exception as error:
    print("DATABASE CHECK FAILED:")
    print(error)
