# emailverif
##### A email address verification script
Taking email addresses from standard input. Output for a correct email address is the input email string otherwise a reason for rejection

---

## Requirements
- Python 3
- ~ 100 KB disk space
---
### Setup & Starting
- After installing python3, open up a terminal window
- Change directory to the folder you want this project to be enclosed within
- Then run `git clone https://github.com/thomasr39/emailverif.git`
- Next run `cd emailverif`
- The project is viewable and editable from this directory
- To run program enter `python3 verification.py` into the terminal
- The program takes email addresses from standard input 

---

## Testing
tested the program by having the program write output to a file named output.txt which it then compares with a file of expected outputs named expected_output.txt. If indicated that the files were different, inspect them with `diff` program in the terminal using `diff output.txt expected_output.txt`

---

## Files
- verification.py - the program
- README.md - read me file
- test.txt - text file of email addresses I used for testing purposes
- expected_output.txt - text file containing expected outputs for testing
- output.txt - generated output of tests
