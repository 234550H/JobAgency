using System.IO;
using System.Security.Cryptography;
using System.Text;

public static class EncryptionHelper
{
    public static byte[] EncryptionKey { get; internal set; }
    public static byte[] IV { get; internal set; }

    // Encrypt data and return as Base64 string
    public static string EncryptData(string plainText, byte[] encryptionKey, byte[] iv)
    {
        using (var aesAlg = Aes.Create())
        {
            aesAlg.Key = encryptionKey; // AES-256 key (32 bytes)
            aesAlg.IV = iv; // AES block size IV (16 bytes)

            using (var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV))
            using (var memoryStream = new MemoryStream())
            using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
            using (var writer = new StreamWriter(cryptoStream))
            {
                writer.Write(plainText);
                writer.Flush();  // Make sure all data is written to the stream

                // Return the encrypted data as a Base64 string
                return Convert.ToBase64String(memoryStream.ToArray());
            }
        }
    }

    // Decrypt data from Base64 string
    public static string DecryptData(string encryptedText, byte[] encryptionKey, byte[] iv)
    {
        var cipherTextBytes = Convert.FromBase64String(encryptedText);

        using (var aesAlg = Aes.Create())
        {
            aesAlg.Key = encryptionKey; // Use the same key for decryption
            aesAlg.IV = iv; // Use the same IV for decryption

            using (var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV))
            using (var memoryStream = new MemoryStream(cipherTextBytes))
            using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
            using (var reader = new StreamReader(cryptoStream))
            {
                // Read the decrypted data and return it as a string
                return reader.ReadToEnd();
            }
        }
    }

    //Decrypt NRIC 
    public static string DecryptNRIC(byte[] encryptedNRIC, byte[] encryptionKey, byte[] iv)
    {
        using (var aesAlg = Aes.Create())
        {
            aesAlg.Key = encryptionKey; // Use the same key for decryption
            aesAlg.IV = iv; // Use the same IV for decryption

            using (var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV))
            using (var memoryStream = new MemoryStream(encryptedNRIC))
            using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
            using (var reader = new StreamReader(cryptoStream))
            {
                // Read the decrypted data (NRIC) and return it as a string
                return reader.ReadToEnd();  
            }
        }
    }


    // Generates a 256-bit key (32 bytes)
    public static byte[] Generate256BitKey()
    {
        using (var rng = new RNGCryptoServiceProvider())
        {
            byte[] key = new byte[32]; // 256 bits = 32 bytes
            rng.GetBytes(key);
            return key;
        }
    }

    // Generates a 128-bit key (16 bytes)
    public static byte[] Generate128BitKey()
    {
        using (var rng = new RNGCryptoServiceProvider())
        {
            byte[] key = new byte[16]; // 128 bits = 16 bytes
            rng.GetBytes(key);
            return key;
        }
    }

    internal static string DecryptData(string firstName, byte[] encryptionKey, object iV)
    {
        throw new NotImplementedException();
    }
}
