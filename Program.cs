using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace ConnectoToShareFolder01
{
    class Program
    {
        static void Main(string[] args)
        {
            // Set the credentials for the remote user
            string remoteUser = "user1";
            string remoteDomain = "bosque1";
            string remotePassword = "hash";
            string keyToDecrypt = "f4f56r412";
            string pathFolderOnServer = @"\\192.168.0.0\FolderUser1User";

            // Set the credentials for the local user
            string localUser = "useraccount";
            string localDomain = "workgroup";
            string localPassword = "password";

            // Impersonate the remote user
            using (new Impersonation(remoteUser, remoteDomain, DecryptString(remotePassword, keyToDecrypt)))            
            {
                // Access the remote folder here                
                try
                {
                    // Upload a pdf file
                    string pdfFile = @"C:\8.pdf";
                    using (FileStream fileStream = new FileStream(pdfFile, FileMode.Open, FileAccess.Read))
                    {
                        // store the file data
                        byte[] fileData = new byte[fileStream.Length];

                        // Read the file dat into the byte array
                        fileStream.Read(fileData, 0, (int)fileStream.Length);

                        string destinationFile = Path.Combine(pathFolderOnServer, Path.GetFileName(pdfFile));

                        // Write data to the destination
                        using (FileStream fileStreamToSave = new FileStream(destinationFile, FileMode.Create, FileAccess.Write))
                        {
                            fileStreamToSave.Write(fileData, 0, fileData.Length);
                        }
                    }

                    // For example, you could use the System.IO.Directory class to list the files in the folder:
                    System.IO.DirectoryInfo directory = new System.IO.DirectoryInfo(pathFolderOnServer);

                    foreach (System.IO.FileInfo file in directory.GetFiles())
                    {
                        Console.WriteLine(file.Name);
                    }
                } catch (Exception ex)
                {
                    Console.WriteLine("\nError: " + ex);
                }
            }

            // Impersonate the local user
            using (new Impersonation(localUser, localDomain, localPassword))
            {
                // Access the local folder here
                // For example, you could use the System.IO.Directory class to list the files in the folder:
                System.IO.DirectoryInfo directory = new System.IO.DirectoryInfo(@"C:\folderTestShare");
                foreach (System.IO.FileInfo file in directory.GetFiles())
                {
                    Console.WriteLine(file.Name);
                }
            }

 

            Console.ReadLine();
        }

        // Decrypt configuration file
        private static string DecryptString(string encryptedDataString, string key)
        {
            try
            {
                byte[] encryptedData = Convert.FromBase64String(encryptedDataString);
                byte[] decryptedData = ProtectedData.Unprotect(encryptedData,
                    Encoding.Unicode.GetBytes(key), DataProtectionScope.CurrentUser);
                string decryptedDataString = Encoding.Unicode.GetString(decryptedData);

                return decryptedDataString;
            } catch (Exception ex)
            {
                Console.WriteLine("\nError: " + ex);
                return null;
            }

        }
    }

    public class Impersonation : IDisposable
    {
        private readonly WindowsImpersonationContext _context;

        public Impersonation(string username, string domain, string password)
        {
            // Impersonate the specified user
            IntPtr token = IntPtr.Zero;
            bool success = LogonUser(username, domain, password, 
                LogonType.LOGON32_LOGON_NEW_CREDENTIALS, 
                LogonProvider.LOGON32_PROVIDER_DEFAULT, out token);
            if (!success)
            {
                int errorCode = Marshal.GetLastWin32Error();
                throw new ApplicationException($"LogonUser failed with error code {errorCode}");
            }

            WindowsIdentity identity = new WindowsIdentity(token);
            _context = identity.Impersonate();
        }

        public void Dispose()
        {
            _context?.Dispose();
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LogonUser(string lpszUsername, string lpszDomain, 
            string lpszPassword, LogonType dwLogonType, LogonProvider dwLogonProvider, 
            out IntPtr phToken);

        public enum LogonType : int
        {
            LOGON32_LOGON_INTERACTIVE = 2,
            LOGON32_LOGON_NETWORK = 3,
            LOGON32_LOGON_BATCH = 4,
            LOGON32_LOGON_SERVICE = 5,
            LOGON32_LOGON_UNLOCK = 7,
            LOGON32_LOGON_NETWORK_CLEARTEXT = 8, // Win2K or higher
            LOGON32_LOGON_NEW_CREDENTIALS = 9 // Win2K or higher
        }

        public enum LogonProvider : int
        {
            LOGON32_PROVIDER_DEFAULT = 0,
            LOGON32_PROVIDER_WINNT35 = 1,
            LOGON32_PROVIDER_WINNT40 = 2,
            LOGON32_PROVIDER_WINNT50 = 3
        }
    }


}

