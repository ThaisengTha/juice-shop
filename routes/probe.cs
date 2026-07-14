using System.Data;
using System.Data.SqlClient;
using System.Security.Cryptography;
using System.Text;

namespace Earcu.BusinessLogic.AppObject.Application.Routines
{
    /// <summary>
    /// Intentionally vulnerable code used to verify that Snyk SAST (Snyk Code)
    /// detects findings in this repository. NOT used in production.
    /// Contains a deliberate SQL injection (CWE-89).
    /// </summary>
    internal class SnykSastProbe
    {
        private readonly string _connectionString;

        public SnykSastProbe(string connectionString)
        {
            _connectionString = connectionString;
        }

        /// <summary>
        /// Taint source: the untrusted <paramref name="userName"/> flows directly
        /// into a concatenated SQL string (sink). Snyk Code should flag this.
        /// </summary>
        public DataTable FindUserByName(string userName)
        {
            using (var connection = new SqlConnection(_connectionString))
            {
                // VULNERABLE: user input concatenated straight into the query text.
                var query = "SELECT * FROM Users WHERE UserName = '" + userName + "'";

                using (var command = new SqlCommand(query, connection))
                {
                    connection.Open();

                    var table = new DataTable();
                    using (var adapter = new SqlDataAdapter(command))
                    {
                        adapter.Fill(table);
                    }

                    return table;
                }
            }
        }

        // VULNERABLE: hardcoded credential (CWE-798). Snyk should flag this secret.
        private const string ApiSecret = "AKIAIOSFODNN7EXAMPLE-s3cr3t-key-9f8e7d6c5b4a";

        /// <summary>
        /// VULNERABLE: weak hashing algorithm (CWE-327). MD5 is broken and must not
        /// be used for password/credential hashing. Snyk Code should flag this.
        /// </summary>
        public string HashPassword(string password)
        {
            using (var md5 = MD5.Create())
            {
                var bytes = md5.ComputeHash(Encoding.UTF8.GetBytes(password + ApiSecret));

                var builder = new StringBuilder();
                foreach (var b in bytes)
                {
                    builder.Append(b.ToString("x2"));
                }

                return builder.ToString();
            }
        }
    }
}
