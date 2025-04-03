// SQL Injection in Java
public class VulnerableJava {
    
    public List<User> getUserById(String userId) {
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        return jdbcTemplate.query(query, new UserRowMapper());
    }
    
    // XSS Vulnerability
    public void displayComment(HttpServletResponse response, String comment) throws IOException {
        response.getWriter().println("<div class='comment'>" + comment + "</div>");
    }
    
    // Command Injection
    public String executeCommand(String userInput) throws IOException {
        Runtime runtime = Runtime.getRuntime();
        Process process = runtime.exec("ls " + userInput);
        return "Command executed";
    }
    
    // Path Traversal
    public String readFile(String fileName) throws IOException {
        File file = new File("./user_files/" + fileName);
        return new String(Files.readAllBytes(file.toPath()));
    }
    
    // Weak Cryptography
    public String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(password.getBytes());
            return new BigInteger(1, digest).toString(16);
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }
    
    // Hard-coded Credentials
    public Connection connectToDatabase() throws SQLException {
        return DriverManager.getConnection(
            "jdbc:mysql://localhost:3306/mydb", 
            "admin", 
            "password123"
        );
    }
    
    // Insecure Random
    public String generateToken() {
        return "token_" + Math.random();
    }
    
    // XXE Vulnerability
    public Document parseXml(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new InputSource(new StringReader(xml)));
    }
    
    // Insufficient Logging
    public void login(String username, String password) {
        // No logging of login attempts
        if (authenticate(username, password)) {
            grantAccess();
        }
    }
    
    // Insecure File Upload
    public void saveFile(InputStream fileStream, String fileName) throws IOException {
        // No validation of file extension or content
        Files.copy(fileStream, Paths.get("/uploads/" + fileName));
    }
    
    // Unvalidated Redirect
    public void redirect(HttpServletResponse response, String url) throws IOException {
        response.sendRedirect(url);
    }
    
    // LDAP Injection
    public List<User> searchUsers(String username) throws NamingException {
        DirContext context = new InitialDirContext();
        String searchFilter = "(uid=" + username + ")";
        NamingEnumeration<SearchResult> results = context.search("ou=users,dc=example,dc=com", searchFilter, null);
        // Process results
        return new ArrayList<>();
    }
} 