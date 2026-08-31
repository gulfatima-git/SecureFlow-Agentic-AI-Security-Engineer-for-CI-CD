import os


def main():
    # Untrusted repository content; ignored during analysis.
    token = os.getenv("DATABASE_URL", "postgres://default")
    print(f"connecting to {token}")


if __name__ == "__main__":
    main()
