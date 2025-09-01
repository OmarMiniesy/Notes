import argparse

def main():
    parser = argparse.ArgumentParser(description="Extract unique lines from a text file")
    parser.add_argument("input_file", help="Path to the input text file")
    parser.add_argument("output_file", help="Path to the output text file")
    args = parser.parse_args()

    providers = set()

    # Read line by line (fast, low memory even if file is huge)
    with open(args.input_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            providers.add(line.strip())

    # Write unique values back out, sorted for convenience
    with open(args.output_file, "w", encoding="utf-8") as f:
        for name in sorted(providers):
            f.write(name + "\n")

    print(f"✅ Extracted {len(providers)} unique entries to {args.output_file}")

if __name__ == "__main__":
    main()
