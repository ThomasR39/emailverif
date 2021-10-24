# Thomas Roff
# Etude 12 
# 05/02/2020 

import re
import sys
import fileinput
import filecmp
import ipaddress

test = True

'''
Function that outouts an error message
Parameter: user_input, error message
'''
def output(user_input, message):
    print(user_input + " <- " + message)
    if test:
        f.write(user_input + " <- " + message + "\n")

'''
Function that takes an email address and formats it correctly.
parameter: email address to format.
return: formatted email.
'''
def tidy_up(address):
    tidy_address = address.lower()
    # replace symbols e.g. _at_ -> @
    tidy_address = tidy_address.replace("_dot_", ".").replace("_at_", "@")
    return tidy_address;

'''
Function that takes an email and finds the domain section
parameter: email address to search for domain in
return: domain string
'''
def find_domain(email):
    domain = re.split("(\.co)|_dot_", email)[0]
    domain = re.split("@|_at_", domain)[1]
    return domain

'''
Function that takes an email address and checks for a valid mailbox.
parameter: email address to proccess and user input.
return: -1 if invalid, 1 if valid
'''
def check_mailbox(email, user_input):
    # mailbox is substring before '@'
    mailbox = re.split("@|_at_", email)[0]
    # check if mailbox matches valid mailbox pattern
    mailbox_match = re.search(mailbox_pattern, mailbox)
    # if there is a match
    if mailbox_match is not None:
        # if the length of the match is less than the mailbox then the match has failed therefore it is wrong
        if len(mailbox_match.group()) < len(mailbox):
            if mailbox[len(mailbox)-1] == "]":
                output(user_input, "@ symbol is not between mailbox and domain")
                return -1
                
            output(user_input, "invalid mailbox, must be alphanumeric (with optional ._- separators)")
            return -1
    # if there no match then it is wrong
    else:
        if mailbox == "":
            output(user_input, "missing mailbox")
            return -1
        elif test:
            output(user_input, "invalid mailbox, must be alphanumeric (with optional ._- separators)")
        return -1
    return 1
        
'''
Function that takes an email and checks if it contains a valid ip adddress
parameter: email to validate ip for and user input.
return: 1 if valid, -1 if invalid
'''
def check_ip(email, user_input):
    domain = find_domain(email)
     # check if domain matches valid domain pattern
    domain_match = re.search(domain_pattern, domain)
    # if there is a match
    
    if domain_match is not None:
        if "[" in domain:
            ip = domain.replace("[", "")
            ip = ip.replace("]", "")
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                output(user_input, "invalid domain, invalid ip")
                return -1
    return 1
'''
Function that takes an email address and checks for a valid domain.
parameter: email address to proccess and user input.
return: -1 if invalid, 1 if valid
'''
def check_domain(email, user_input):
    try:
        domain = find_domain(email)
    except IndexError as error:
        output(user_input, "@ symbol is not between mailbox and domain")
        return -1
    
    if domain == "[]":
        output(user_input, "invalid domain, missing ip")
        return -1
    elif domain == "":
        output(user_input, "missing domain")
        return -1
 
    if "]" in domain or "[" in domain:
        if "[" in domain and "]" in domain:
            for char in domain:
                if char not in ['[', ']', '.'] or not char.isnumeric():
                    output(user_input, "invalid ip, contains invalid characters")
                    return -1
        elif "[" in domain:
            output(user_input, "invalid domain, missing ] bracket")
            return -1
        elif "]" in domain:
            output(user_input, "invalid domain, missing [ bracket")
            return -1
            
    else:
        matched = re.match("[\d\.]+", domain)
        if matched:
            if not ('.co.nz' in email) and ('.com.au' in email) and ('.co.uk' in email) and ('.com.ca' in email) and ('.co.us' in email) and ('.com' in email):
                output(user_input, "invalid domain, missing brackets")
                return -1
    
    # check if domain matches valid domain pattern
    domain_match = re.search(domain_pattern, domain)
    # if there is a match
 
    if domain_match is not None:
        # if the length of the match is less than the domain then it has failed
        if len(domain_match.group()) < len(domain):
            output(user_input, "invalid domain, must be alphanumeric (with optional . separators)")
            return -1
            
    # if there is no match then it has failed
    else:
        if test:
            output(user_input, "invalid domain, must be alphanumeric (with optional . separators)")
        return -1
    return 1
    
'''
Function that takes an email address and checks for a valid domain extension.
parameter: email address to proccess and user input.
return: -1 if invalid, 1 if valid
'''
def check_extension(email, user_input):
    
    domain = find_domain(email)
    if domain in ['co.nz','com.au','co.ca','com','co.us','co.uk']:
        output(user_input, "missing domain")
        return -1
        
    # extension is after domain
    extension = re.split(domain, email)[1]
    # check if extension matches valid extension pattern
    extension_match = re.search("(.|_dot_)" + extension_pattern, extension)
    # if there is a match
    if extension_match is not None:
        # if the length of the match is less than the extension then it has failed
        if len(extension_match.group()) < len(extension):
            output(user_input, "invalid extension")
            return -1
    # if there is no match then it has failed        
    elif extension == "@":
        output(user_input, "missing extension")
        return -1
    else:
        output(user_input, "invalid extension")
        return -1
    return 1

'''
Function that takes an email address and checks if it contains '@' or '_at_.
parameter: email address to proccess and user input.
return: -1 if invalid, 1 if valid
''' 
def check_at(email, user_input):
    # if there is no @ symbol
    if re.search("@|_at_", email) is None:
        output(user_input, "missing @ symbol")
        return -1
    else:
        i = 0;
        count = 0
        while i < len(email):
            if email[i] == "@":
                count += 1
            i += 1
        if count > 1:
            output(user_input, "invalid email, multiple @ symbols")
            return -1
        
    return 1
    

'''
Function that takes an email address and checks against rules for .-_ characters
parameter: email address to proccess and user input.
return: -1 if invalid, 1 if valid
'''
def check_for_consecutive(email, user_input):
    i = 1
    while i < len(email):        
        # check for .-_ in first character
        if i == 1:
            if email[0] == "_" or email[0] == "." or email[0] == "-":
                output(user_input, "invalid mailbox, " + email[0] + " is not acting as a separator")
                return -1
        
        if email[i] == "_" or email[i] == "." or email[i] == "-":
            # check for consecutive .-_
            if email[i] == email[i-1]:
                output(user_input, "invalid email, consecutive " + email[i])
                return -1
            elif email[i-1] in ".-_":
                output(user_input, "invalid mailbox, " + email[i]  + " is not acting as a separator")
                return -1
            # check for .-_ in last character if mailbox
            elif i != len(email) -1  and email[i+1] == "@":
                output(user_input, "invalid mailbox, " + email[i]  + " is not acting as a separator")
                return -1
            # check for .-_ in first character of domain
            elif email[i-1] == "@":
                output(user_input, "invalid domain, " + email[i]  + " is not acting as a separator")
                return -1
            # check for .-_ in last character of domain
            elif i != len(email)-1 and email[i+1:len(email)] in (".com", ".co.nz", ".co.uk", ".com.au", ".co.us"):
                output(user_input, "invalid domain, " + email[i]  + " is not acting as a separator")
                return -1
        i +=1
    return 1


# regex patterns #          
valid_email_pattern = "[A-Za-z0-9\._-]+(@|_at_)(\[[\d\.]+\]|[A-Za-z0-9\.]+(\.|_dot_)(co\.nz|com\.au|co\.ca|com|co\.us|co\.uk))"
domain_pattern = "(\[[\d\.]+\]|[A-Za-z0-9\.])+"
mailbox_pattern = "[A-Za-z0-9\._-]+"
extension_pattern = "(co\.nz|com\.au|co\.ca|com|co\.us|co\.uk)"

if test == True:
    f= open("output.txt","w+")
    
for email in fileinput.input():
    # if input is empty then display error
    if ' ' in email:
        output(email.strip(), "invalid email, contains white space")
        continue;
    email = email.strip() # removes new line
    if email == "":
        continue
     
    bad_extension = False
    invalid_extensions = ["co_dot_nz", "com_dot_au", "co_dot_ca", "co_dot_us", "co_dot_uk"]
    for extension in invalid_extensions:
        if extension in email:
            bad_extension = True
            continue
            
    if bad_extension:
        output(email, "invalid extension")
        continue
      
    address = tidy_up(email)

    # check if email entered matches valid email pattern
    match = re.search(valid_email_pattern, address)

    bracket_present = False

    # if there is a match and it is the same length of the email then it should be correct
    if match is not None and len(match.group()) == len(address):
        if "[" in address:
            if check_ip(address, email) == -1:
                continue
        if check_for_consecutive(address, email) == -1:
            continue
        
    else:
        # check all parts of email for errors
        if check_at(address, email) == -1:
            continue
        if check_mailbox(address, email) == -1:
            continue
        if check_domain(address, email) == -1:
            continue
        if check_extension(address, email) == -1:
            continue
    
    if test:
        f.write(address+"\n")
    print(address)

if test:
    f.close()
    if filecmp.cmp("output.txt", "expected_output.txt", shallow=False):
        print("same")
    else:
        print("not same")
