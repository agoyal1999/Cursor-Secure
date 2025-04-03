// SQL Injection in C#
using System;
using System.Data.SqlClient;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Web;

public class VulnerableCSharp
{
    // SQL Injection
    public void GetUserById(string userId)
    {
        string connectionString = "Data Source=localhost;Initial Catalog=mydb;User ID=sa;Password=secretpassword";
        SqlConnection connection = new SqlConnection(connectionString);
        connection.Open();

        string query = "SELECT * FROM Users WHERE Id = '" + userId + "'";
        SqlCommand command = new SqlCommand(query, connection);
        SqlDataReader reader = command.ExecuteReader();
        
        // Process results
        connection.Close();
    }

    // XSS Vulnerability
    public void DisplayComment(HttpResponse Response, string comment)
    {
        Response.Write("<div class='comment'>" + comment + "</div>");
    }

    // Command Injection
    public string ExecuteCommand(string userInput)
    {
        System.Diagnostics.Process process = new System.Diagnostics.Process();
        process.StartInfo.FileName = "cmd.exe";
        process.StartInfo.Arguments = "/c dir " + userInput;
        process.Start();
        return "Command executed";
    }

    // Path Traversal
    public string ReadFile(string fileName)
    {
        return File.ReadAllText("./user_files/" + fileName);
    }

    // Weak Cryptography
    public string HashPassword(string password)
    {
        using (MD5 md5 = MD5.Create())
        {
            byte[] inputBytes = Encoding.ASCII.GetBytes(password);
            byte[] hashBytes = md5.ComputeHash(inputBytes);
            
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < hashBytes.Length; i++)
            {
                sb.Append(hashBytes[i].ToString("X2"));
            }
            return sb.ToString();
        }
    }

    // Hard-coded Credentials
    public SqlConnection ConnectToDatabase()
    {
        string connectionString = "Data Source=localhost;Initial Catalog=mydb;User ID=admin;Password=password123";
        SqlConnection connection = new SqlConnection(connectionString);
        connection.Open();
        return connection;
    }

    // Insecure Random
    public string GenerateToken()
    {
        Random random = new Random();
        return "token_" + random.Next(100000, 999999).ToString();
    }

    // XXE Vulnerability
    public void ParseXml(string xml)
    {
        System.Xml.XmlDocument doc = new System.Xml.XmlDocument();
        doc.XmlResolver = new System.Xml.XmlUrlResolver();
        doc.LoadXml(xml);
    }

    // LDAP Injection
    public void SearchUsers(string username)
    {
        string filter = "(uid=" + username + ")";
        // LDAP search with filter
    }

    // Insecure Deserialization
    public object DeserializeObject(string serializedData)
    {
        System.Runtime.Serialization.Formatters.Binary.BinaryFormatter formatter = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
        using (MemoryStream ms = new MemoryStream(Convert.FromBase64String(serializedData)))
        {
            return formatter.Deserialize(ms);
        }
    }

    // Unvalidated Redirect
    public void RedirectUser(HttpResponse Response, string url)
    {
        Response.Redirect(url);
    }
} 