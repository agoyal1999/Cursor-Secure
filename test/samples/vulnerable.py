# SQL Injection in Python
def get_user_by_id(user_id):
    query = "SELECT * FROM users WHERE id = %s" % user_id
    cursor.execute(query)
    return cursor.fetchall()

# XSS in Python
def display_comment(request, comment_id):
    comment = get_comment(comment_id)
    response.write("<div class='comment'>" + comment + "</div>")
    return response

# Command Injection
def run_command(user_input):
    import os
    os.system("ls " + user_input)
    return "Command executed"

# Path Traversal
def get_file(filename):
    with open("./user_files/" + filename, "r") as f:
        return f.read()

# Weak Cryptography
def hash_password(password):
    import hashlib
    return hashlib.md5(password.encode()).hexdigest()

# Insecure Deserialization
def process_data(user_data):
    import pickle
    return pickle.loads(user_data)

# SSRF Vulnerability
def fetch_url(url):
    import urllib.request
    return urllib.request.urlopen(url).read()

# Hard-coded Credentials
def connect_to_database():
    password = "admin123"
    connection = connect("localhost", "admin", password)
    return connection

# Insecure Random Values
def generate_token():
    import random
    return "token_" + str(random.random())

# XML External Entity (XXE)
def parse_xml(xml_data):
    from xml.dom.minidom import parseString
    return parseString(xml_data)

# Flask Route with No Input Validation
def user_profile(user_id):
    return render_template("profile.html", user=get_user(user_id))

# Django SQL Injection
def search_users(request):
    query = request.GET.get('q', '')
    raw_sql = "SELECT * FROM auth_user WHERE username LIKE '%" + query + "%'"
    return User.objects.raw(raw_sql) 