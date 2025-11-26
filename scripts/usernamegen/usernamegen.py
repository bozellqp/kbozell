import sys
import argparse

#Arguments
parser = argparse.ArgumentParser(description="Generates a list of usernames from a list of names.")
parser.add_argument("input", help = "Text file with names.")
parser.add_argument("output", help = "Name of resutling file.")
parser.add_argument("--middlenames", "-m", action="store_true", help = "Process middle names / two last names.")
parser.add_argument("--go_crazy", "-g", action="store_true", help = "Include non-standard combinations.")
parser.add_argument("--case_sensitive", "-c", action="store_true", help = "Add capitalization variants. All lowercase if disabled.")
args = parser.parse_args()

#Load input file, turn ino lines
names = []
with open(args.input, "r") as f:
    for line in f:
        parts = line.strip().split()
        if args.middlenames:
            if len(parts) !=3:
                print(f"Error: Make sure the elements of {args.input} are formatted like: \"First Middle Last\"")
                sys.exit(1)
            first, middle, last  = parts
            names.append((first, middle, last))
        else:
            if len(parts) !=2:
                print(f"Error: Make sure the elements of {args.input} are formatted like: \"First Last\"")
                sys.exit(1)
            first, last  = parts
            names.append((first, last))

def generate_list(names, output, middlenames, go_crazy, case_sensitive):
    usernames = set()
    for member in names:
         # --- NO MIDDLE NAMES ---
        if not middlenames:
            first, last = member
            # COMMON patterns
            usernames.add(first + last)
            usernames.add(first + "." + last)
            usernames.add(first + "_" + last)
            usernames.add(first[0] + last)
            usernames.add(first[0] + "." + last)
            usernames.add(first[0] + "_" + last)
            usernames.add(first + last[0])
            usernames.add(last + first)
            usernames.add(last + "." + first)
            usernames.add(last + "_" + first)
            usernames.add(last[0] + first)
            # EXTENDED patterns
            if go_crazy:
                usernames.add(last[0] + "_" + first)
                usernames.add(first + "-" + last)
                usernames.add(first[0] + "-" + last)
                usernames.add(last + "-" + first)
                usernames.add(last[0] + "-" + first)
                usernames.add(first + last + last[0])
                usernames.add(first[0] + last + last[0])
                usernames.add(first[0] + last[0])
                usernames.add(first[0] + "." + last[0])
                usernames.add(first[0] + "_" + last[0])
                usernames.add(first + "." + last + last[0])
                usernames.add(first + "_" + last + last[0])
                usernames.add(first[0] + "." + last + last[0])
                usernames.add(first[0] + "_" + last + last[0])
                usernames.add(last + first + last[0])
                usernames.add(last[0] + first + last[0])
        # --- MIDDLE NAMES ---
        else:
            first, middle, last = member
            # COMMON patterns
            usernames.add(first + last)
            usernames.add(first + middle + last)
            usernames.add(first + "." + last)
            usernames.add(first + "." + middle + "." + last)
            usernames.add(first[0] + last)
            usernames.add(first[0] + middle[0] + last)
            usernames.add(first + last[0])
            usernames.add(first + middle[0] + last)
            usernames.add(first[0] + middle[0] + last[0])
            # EXTENDED patterns
            if go_crazy:
                usernames.add(first + last[0])
                usernames.add(first + middle[0] + last)
                usernames.add(first + middle[0] + last[0])
                usernames.add(first[0] + middle + last)
                usernames.add(first[0] + middle + last[0])
                usernames.add(first + "_" + last)
                usernames.add(first + "." + middle + last)
                usernames.add(first + "_" + middle + last)
                usernames.add(first + middle + "." + last)
                usernames.add(first + middle + "_" + last)
                usernames.add(first[0] + "." + middle[0] + "." + last[0])
                usernames.add(first + "-" + middle + "-" + last)
                usernames.add(first[0] + "-" + middle[0] + "-" + last)
                usernames.add(last + first + middle)
                usernames.add(last[0] + first[0] + middle[0])
                usernames.add(middle + last)
                usernames.add(middle[0] + last)
                usernames.add(middle[0] + last[0])
                usernames.add(first + middle)
                usernames.add(first[0] + middle)
                usernames.add(first + middle[0])
                usernames.add(middle + first + last)
                usernames.add(middle + "." + first + "." + last)
                usernames.add(middle + "_" + first + "_" + last)

    final_usernames = set()
    for username in usernames:
        final_usernames.add(username.lower())
        if case_sensitive:
            final_usernames.add(username.upper())
            final_usernames.add(username.title())
    with open(output, "w") as g:
        for u in sorted(final_usernames):
            g.write(u + "\n")
    print("Generating wordlist...")


if __name__ == "__main__":
    generate_list(names, args.output, args.middlenames, args.go_crazy, args.case_sensitive)
    print(f"Done! Your wordlist is stored in {args.output}")
