# PAAT: Password Audit and Analysis Tool

A Python script that checks the strength of provided passwords and identifies potential issues.
## Features / Checks

- **Breach-list**: Queries the "Have I Been Pwned" API to check if the password has been compromised in previous data breaches.
- **NZISM Compliance**: Checks if the password complies with the New Zealand Information Security Manual (NZISM) requirements.
- **NIST Compliance**: Checks if the password complies with the National Institute of Standards and Technology (NIST) guidelines.
- **Common Words**: Checks if the password is based on common English words.
- **Keyboard Patterns**: Identifies if the password contains keyboard patterns (e.g., "qwerty" or "12345").
- **Repeated Characters**: Checks for repeated patterns of characters (e.g., "aaa" or "111").
- **Sequential Characters**: Identifies sequential characters (e.g., "abc" or "123").
- **Calendar Years**: Checks for the presence of calendar years in the password (currently limited to full calendar year - e.g., "1920" or "2023")
- **Leet Speak**: Detects if the password uses l33t speak substitutions of common words.
- **Password Strength**: Attempts to evaluate the overall strength of the password based on the previous criteria.
- **Custom Wordlists**: Supports custom wordlists provided by the user.
- **Password Recommendations**: Provides recommendations for password improvement based on identified issues.

## Usage

- `-p` or `--password`: Check the strength of a single password.
- `-P` or `--passwords`: Check a list of passwords stored in a text file.
- `-w` or `--wordlists`: Specify custom wordlist files for additional checks (optional).
- `-r` or `--recommendations`: Show password recommendations (optional).
- `-t` or `--threads`: Specify the maximum number of threads for concurrent processing (default: 50, optional).

## Limitations

- The wordlists (such as common words) included in this repo are not exhaustive. You may want to source your own custom wordlists. A good resource: https://github.com/mamatb/OneWordlistToListThemAll/blob/master/README.md#wordlists. 
- The script does not check for weak passwords as it already checks 'Have I Been Pwned'.
- Password strength is a bit hit and miss.
- Output is currently only printed to terminal, easy to redirect output or perhaps add outputting to csv in future.

## Acknowledgments

- The script uses the "Have I Been Pwned" API to check for breached passwords.