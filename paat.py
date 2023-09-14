import requests
import hashlib
import argparse
import string
import re
import sys
from colorama import Fore, Style
import concurrent.futures
import threading


COMMON_PASSWORDS_FILE = "common_passwords.txt"
KEYBOARD_PATTERNS_FILE = "keyboard_patterns.txt"
COMMON_WORDS_FILE = "common_words.txt"

custom_words_data = []
total_passwords_audited = 0
total_nzism_failure_count = 0
total_nist_failure_count = 0
total_in_breachlist = 0
password_score = 0


def print_banner():
    banner = f"""{Fore.CYAN}
                ╔════════════════════════════════════════╗
                ║    Password Audit and Analysis Tool    ║
                ║      Author: phish (@dunderhay)        ║
                ╚════════════════════════════════════════╝{Style.RESET_ALL}
    """
    print(banner)
    print("=" * 80)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="PAAT: Password Audit and Analysis Tool",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Usage examples:"
        "\n  python3 pat.py -p Password123"
        "\n  python3 pat.py -P password_file.txt"
        "\n  python3 pat.py -P password_file.txt -w customwordlist1.txt customwordlist2.txt",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-p", "--password", help="Single password to check", metavar=("Password123")
    )
    group.add_argument(
        "-P",
        "--passwords",
        help="Path to a password file to check",
        metavar=("password_list.txt"),
    )
    parser.add_argument(
        "-w",
        "--wordlists",
        nargs="+",
        help="Custom wordlist files to check against\nYou can specify one or more files separated by spaces",
    )
    parser.add_argument(
        "-r",
        "--recommendations",
        action="store_true",
        default=False,
        help="Show password recommendations",
    )
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=50,
        help="Maximum number of threads (default: 50)",
    )
    return parser.parse_args()


def load_custom_wordlists(wordlist_files):
    custom_words = []
    for file_path in wordlist_files:
        custom_words.extend(load_data_from_file(file_path))
    return custom_words


def load_data_from_file(file_path):
    try:
        with open(file_path, "r") as file:
            data = [line.strip() for line in file]
        return data
    except FileNotFoundError:
        print(f"{Fore.RED}[!] File not found: {file_path}{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[!] An error occurred: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)


common_passwords_data = load_data_from_file(COMMON_PASSWORDS_FILE)
keyboard_patterns_data = load_data_from_file(KEYBOARD_PATTERNS_FILE)
common_words_data = load_data_from_file(COMMON_WORDS_FILE)


def print_audit_results(
    total_passwords_audited,
    total_nzism_failure_count,
    total_nist_failure_count,
    total_in_breachlist,
):
    nzism_percentage = (
        (total_nzism_failure_count / total_passwords_audited) * 100
        if total_passwords_audited > 0
        else 0
    )
    nist_percentage = (
        (total_nist_failure_count / total_passwords_audited) * 100
        if total_passwords_audited > 0
        else 0
    )
    breachlist_percentage = (
        (total_in_breachlist / total_passwords_audited) * 100
        if total_passwords_audited > 0
        else 0
    )

    print("-" * 28 + " Overall Audit Results " + "-" * 29)
    print("=" * 80)
    print(f"[*] Passwords audited: {total_passwords_audited}")
    print(
        f"[*] Failed NZISM compliance: {total_nzism_failure_count} ({nzism_percentage:.2f}%)"
    )
    print(
        f"[*] Failed NIST compliance: {total_nist_failure_count} ({nist_percentage:.2f}%)"
    )
    print(
        f"[*] Found in breach-list ('Have I Been Pwned'): {total_in_breachlist} ({breachlist_percentage:.2f}%)"
    )


def check_pwned_password(password):
    try:
        sha1_password = hashlib.sha1(password.encode()).hexdigest().upper()
        # Separate the first 5 characters of the hash (prefix) and the rest (suffix)
        prefix, suffix = sha1_password[:5], sha1_password[5:]
        # Send a request to the Have I Been Pwned API to get a list of suffixes
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
        if response.status_code == 200:
            # Check if the suffix of the password hash is in the response
            hashes = (line.split(":") for line in response.text.splitlines())
            for h, count in hashes:
                if h == suffix:
                    return True, int(count)

    except requests.exceptions.RequestException as req_err:
        print(
            f"{Fore.RED}[!] Error connecting to the 'Have I Been Pwned' API: {req_err}{Style.RESET_ALL}"
        )
    except Exception as e:
        print(f"{Fore.RED}[!] An error occurred: {str(e)}{Style.RESET_ALL}")

    # Password not found in the breachlist
    return False, 0


def check_nzism_compliant(password):
    nzism_compliance_failure = []
    nzism_compliance_recommendation = []

    # Password is compliant
    if len(password) >= 16:
        return (
            nzism_compliance_failure,
            nzism_compliance_recommendation,
        )

    character_sets = [
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        string.punctuation,
    ]

    complexity_requirement = 0

    for char_set in character_sets:
        if any(char in char_set for char in password):
            complexity_requirement += 1

    # Password is compliant
    if len(password) >= 10 and complexity_requirement >= 3:
        return (
            nzism_compliance_failure,
            nzism_compliance_recommendation,
        )

    if len(password) >= 10 and complexity_requirement < 3:
        nzism_compliance_failure.append(
            "Password is longer than 10 characters but doesn't meet complexity requirements"
        )
        nzism_compliance_recommendation.append(
            "NZISM: Password length should be a minimum of 10 characters with complexity or 16 characters without complexity"
        )
        nzism_compliance_recommendation.append(
            "NZISM: Include characters from at least three of the following sets: lowercase, uppercase, digits, or special characters"
        )

    if len(password) < 10:
        nzism_compliance_failure.append("Password is too short")
        nzism_compliance_recommendation.append(
            "NZISM: Password length should be a minimum of 10 characters with complexity or 16 characters without complexity"
        )
        nzism_compliance_recommendation.append("NZISM: Increase password length")

    return nzism_compliance_failure, nzism_compliance_recommendation


def check_nist_compliant(password):
    nist_compliance_failure = []
    nist_compliance_recommendation = []

    # Password is compliant
    if len(password) >= 8:
        return (
            nist_compliance_failure,
            nist_compliance_recommendation,
        )

    if len(password) < 8:
        nist_compliance_failure.append("Password is too short")
        nist_compliance_recommendation.append(
            "NIST: Password length should be a minimum of 8 characters"
        )

    return nist_compliance_failure, nist_compliance_recommendation


def check_common_password(password):
    return password.lower() in (
        common_password.lower() for common_password in common_passwords_data
    )


def check_common_words(password):
    matching_words = []

    for word in common_words_data:
        word = word.lower()
        if word in password.lower().split():
            matching_words.append(word)

    matching_words.sort(key=len, reverse=True)

    return matching_words[0] if matching_words else None


def check_custom_wordlist(password):
    matching_word = next(
        (
            custom_word
            for custom_word in custom_words_data
            if custom_word.lower() in password.lower()
        ),
        None,
    )
    return matching_word


def check_keyboard_pattern(password):
    found_patterns = []

    longest_match = ""

    for pattern in keyboard_patterns_data:
        regex_pattern = re.compile(rf"(?i){re.escape(pattern)}+")
        matches = regex_pattern.finditer(password)

        for match in matches:
            if len(match.group(0)) > len(longest_match):
                longest_match = match.group(0)

    if longest_match:
        found_patterns.append(longest_match)

    return found_patterns


def check_repeated_characters(password):
    repeated_patterns = []
    regex_pattern = r"(\w)\1{2,}"

    for match in re.finditer(regex_pattern, password):
        repeated_patterns.append(match.group(0))

    return repeated_patterns


def is_alphabetical_sequence(sequence):
    sequence = sequence.lower()
    sequential_alpha_pattern = []

    i = 0
    while i < len(sequence):
        j = i + 1
        while j < len(sequence) and ord(sequence[j]) == ord(sequence[i]) + (j - i):
            j += 1
        if j - i >= 3:
            sequential_alpha_pattern.append("".join(sequence[i:j]))
        i = j

    return sequential_alpha_pattern


def is_numeric_sequence(sequence):
    numbers = list(map(int, list(sequence)))
    sequential_numeric_pattern = []

    i = 0
    while i < len(numbers):
        j = i + 1
        while j < len(numbers) and numbers[j] == numbers[i] + (j - i):
            j += 1
        if j - i >= 3:
            sequential_numeric_pattern.append("".join(map(str, numbers[i:j])))
        i = j

    return sequential_numeric_pattern


def check_sequential_characters(password):
    found_sequences = []
    alpha_sequences = re.findall(r"[a-zA-Z]+", password)
    numeric_sequences = re.findall(r"\d+", password)
    for sequence in alpha_sequences:
        sequential_alpha_pattern = is_alphabetical_sequence(sequence)
        if sequential_alpha_pattern:
            found_sequences.extend(sequential_alpha_pattern)
    for sequence in numeric_sequences:
        sequential_numeric_pattern = is_numeric_sequence(sequence)
        if sequential_numeric_pattern:
            found_sequences.extend(sequential_numeric_pattern)

    return found_sequences


leet_speak_mapping = {
    "4": "a",
    "@": "a",
    "3": "e",
    "1": "i",
    "0": "o",
    "5": "s",
    "7": "t",
}


def check_leet_speak(password):
    for leet_char, real_char in leet_speak_mapping.items():
        password = password.replace(leet_char, real_char)
    if password in common_words_data:
        return True
    if password in common_passwords_data:
        return True
    return False


def check_calendar_year(password):
    year_pattern = re.compile(r"(\d{4})")
    match = year_pattern.search(password)
    if match:
        year = int(match.group())
        if 1700 <= year <= 2099:
            return year
    return None


def password_strength_meter(password_score):
    password_score = max(0, min(password_score, 10))
    if password_score == 10:
        return f"{Fore.GREEN}Very Strong{Style.RESET_ALL}"
    elif password_score >= 8:
        return f"{Fore.GREEN}Strong{Style.RESET_ALL}"
    elif password_score >= 6:
        return f"{Fore.YELLOW}Moderate{Style.RESET_ALL}"
    elif password_score >= 3:
        return f"{Fore.RED}Weak{Style.RESET_ALL}"
    else:
        return f"{Fore.RED}Very Weak{Style.RESET_ALL}"


thread_lock = threading.Lock()


def process_password(password, show_recommendations):
    global total_passwords_audited
    global total_nzism_failure_count
    global total_nist_failure_count
    global total_in_breachlist
    global password_score

    recommendations = []
    has_leet_speak = None
    has_custom_word = None

    in_breachlist, pwned_count = check_pwned_password(password)
    nzism_compliance_failure, nzism_compliance_recommendation = check_nzism_compliant(
        password
    )
    nist_compliance_failure, nist_compliance_recommendation = check_nist_compliant(
        password
    )
    is_common_password = check_common_password(password)
    has_common_word = check_common_words(password)
    if custom_words_data:
        has_custom_word = check_custom_wordlist(password)
    has_keyboard_patterns = check_keyboard_pattern(password)
    has_repeated_patterns = check_repeated_characters(password)
    has_sequence_characters = check_sequential_characters(password)
    leet_detected = any(char in leet_speak_mapping for char in password)
    if leet_detected:
        has_leet_speak = check_leet_speak(password)
    has_calendar_year = check_calendar_year(password)

    total_passwords_audited += 1

    with thread_lock:
        print(f"[*] Candidate: {password}")

        if in_breachlist:
            total_in_breachlist += 1
            password_score -= 5
            print(
                f"{Fore.YELLOW}[-] Found in breach-list ('Have I Been Pwned'): {Fore.RED}{pwned_count} times{Style.RESET_ALL}"
            )
            recommendations.append("Avoid passwords found in breach-lists")

        if not in_breachlist:
            password_score += 2

        if nzism_compliance_failure:
            total_nzism_failure_count += 1
            password_score -= 2
            print(
                f"{Fore.YELLOW}[-] NZISM compliance failure: {Fore.RED}{nzism_compliance_failure[0]}{Style.RESET_ALL}"
            )
            recommendations.extend(nzism_compliance_recommendation)

        if nist_compliance_failure:
            total_nist_failure_count += 1
            password_score -= 2
            print(
                f"{Fore.YELLOW}[-] NIST compliance failure: {Fore.RED}{nist_compliance_failure[0]}{Style.RESET_ALL}"
            )
            recommendations.extend(nist_compliance_recommendation)

        if not nzism_compliance_failure:
            password_score += 1

        if not nist_compliance_failure:
            password_score += 1

        if is_common_password:
            password_score -= 4
            print(f"{Fore.YELLOW}[-] Found in common password list{Style.RESET_ALL}")
            recommendations.append("Avoid using common passwords")

        if not is_common_password:
            password_score += 1

        if has_common_word:
            password_score -= 3
            print(
                f"{Fore.YELLOW}[-] Based on a common word: {Fore.RED}{has_common_word}{Style.RESET_ALL}"
            )
            recommendations.append(
                "Avoid using common words as the basis for your password"
            )

        if has_custom_word:
            password_score -= 2
            print(
                f"{Fore.YELLOW}[-] Based on a custom word: {Fore.RED}{has_custom_word}{Style.RESET_ALL}"
            )

        if not has_common_word:
            password_score += 1

        if has_keyboard_patterns:
            password_score -= 2
            print(
                f"{Fore.YELLOW}[-] Contains keyboard patterns: {Fore.RED}{', '.join(has_keyboard_patterns)}{Style.RESET_ALL}"
            )
            recommendations.append("Avoid using common keyboard patterns")

        if has_repeated_patterns:
            password_score -= 2
            print(
                f"{Fore.YELLOW}[-] Contains repeated patterns: {Fore.RED}{', '.join(has_repeated_patterns)}{Style.RESET_ALL}"
            )
            recommendations.append("Avoid using consecutive characters")

        if not has_repeated_patterns:
            password_score += 1

        if has_sequence_characters:
            password_score -= 2
            print(
                f"{Fore.YELLOW}[-] Contains sequential characters: {Fore.RED}{', '.join(has_sequence_characters)}{Style.RESET_ALL}"
            )
            recommendations.append("Avoid using sequential characters")

        if not has_sequence_characters:
            password_score += 1

        if has_leet_speak:
            password_score -= 1
            print(
                f"{Fore.YELLOW}[-] Uses l33t speak substitutions of common words or passwords{Style.RESET_ALL}"
            )
            recommendations.append(
                "Avoid using l33t speak substitution of common words or passwords"
            )

        if not has_leet_speak:
            password_score += 1

        if has_calendar_year:
            password_score -= 1
            print(
                f"{Fore.YELLOW}[-] Contains calendar year: {Fore.RED}{has_calendar_year}{Style.RESET_ALL}"
            )
            recommendations.append("Avoid using calendar years")

        if not has_calendar_year:
            password_score += 1

        password_strength = password_strength_meter(password_score)
        print(f"[*] Password score: {password_strength}")
        password_score = 0

        if not any(
            [
                in_breachlist,
                nzism_compliance_failure,
                is_common_password,
                has_common_word,
                has_custom_word,
                has_keyboard_patterns,
                has_keyboard_patterns,
                has_sequence_characters,
                has_leet_speak,
            ]
        ):
            print(
                f"{Fore.GREEN}[+] Passed all checks without obvious issues{Style.RESET_ALL}"
            )

        if recommendations and show_recommendations:
            print(f"{Fore.CYAN}", end="")
            print("-" * 27 + " Password Recommendations " + "-" * 27)
            print(f"{Style.RESET_ALL}", end="")
            for recommendation in recommendations:
                print(f"[*] {recommendation}")

        print("=" * 80)


def process_password_list(file_path, max_threads, show_recommendations):
    passwords = load_data_from_file(file_path)
    if passwords:
        with concurrent.futures.ThreadPoolExecutor(max_threads) as executor:
            futures = []
            for password in passwords:
                future = executor.submit(
                    process_password, password, show_recommendations
                )
                futures.append(future)

            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as exc:
                    print(f"[*] Password processing failed: {exc}")
    else:
        print(f"[!] No passwords found in file: {file_path}")


def main(args):
    global custom_words_data
    print_banner()
    try:
        if args.wordlists:
            custom_words_data = load_custom_wordlists(args.wordlists)

        if args.password:
            process_password(args.password, args.recommendations)
        if args.passwords:
            process_password_list(args.passwords, args.threads, args.recommendations)

        # Print audit results regardless of the chosen path
        print_audit_results(
            total_passwords_audited,
            total_nzism_failure_count,
            total_nist_failure_count,
            total_in_breachlist,
        )

    except KeyboardInterrupt:
        print("\nCtrl + C detected. Exiting the script")
        sys.exit(0)


if __name__ == "__main__":
    args = parse_arguments()
    main(args)
