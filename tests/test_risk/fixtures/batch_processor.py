"""Fixture: a nightly batch ETL — batch_offline + no sensitive data."""
import argparse


def process_batch(rows: list) -> int:
    batch_size = 1000
    return len(rows) // batch_size


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input")
    args = parser.parse_args()
    print(args.input)
