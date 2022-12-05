using System.Security.Cryptography;
using System.Text;
using static System.Security.Cryptography.RSACryptoServiceProvider;

namespace ZKI7;

class Program
{
    static void Main(string[] args)
    {
        /*try
        {
            //Create a UnicodeEncoder to convert between byte array and string.
            UnicodeEncoding ByteConverter = new UnicodeEncoding();

            //Create byte arrays to hold original, encrypted, and decrypted data.
            byte[] dataToEncrypt = ByteConverter.GetBytes("Data to Encrypt");
            byte[] encryptedData;
            byte[] decryptedData;

            //Create a new instance of RSACryptoServiceProvider to generate
            //public and private key data.
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {

                //Pass the data to ENCRYPT, the public key information 
                //(using RSACryptoServiceProvider.ExportParameters(false),
                //and a boolean flag specifying no OAEP padding.
                encryptedData = RSAEncrypt(dataToEncrypt, RSA.ExportParameters(false), false);

                //Pass the data to DECRYPT, the private key information 
                //(using RSACryptoServiceProvider.ExportParameters(true),
                //and a boolean flag specifying no OAEP padding.
                decryptedData = RSADecrypt(encryptedData, RSA.ExportParameters(true), false);

                //Display the decrypted plaintext to the console. 
                Console.WriteLine("Decrypted plaintext: {0}", ByteConverter.GetString(decryptedData));
            }
        }
        catch (ArgumentNullException)
        {
            //Catch this exception in case the encryption did
            //not succeed.
            Console.WriteLine("Encryption failed.");
        }
    }

    public static byte[] RSAEncrypt(byte[] DataToEncrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
    {
        try
        {
            byte[] encryptedData;
            //Create a new instance of RSACryptoServiceProvider.
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {

                //Import the RSA Key information. This only needs
                //toinclude the public key information.
                RSA.ImportParameters(RSAKeyInfo);

                //Encrypt the passed byte array and specify OAEP padding.  
                //OAEP padding is only available on Microsoft Windows XP or
                //later.  
                encryptedData = RSA.Encrypt(DataToEncrypt, DoOAEPPadding);
            }
            return encryptedData;
        }
        //Catch and display a CryptographicException  
        //to the console.
        catch (CryptographicException e)
        {
            Console.WriteLine(e.Message);

            return null;
        }
    }

    public static byte[] RSADecrypt(byte[] DataToDecrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
    {
        try
        {
            byte[] decryptedData;
            //Create a new instance of RSACryptoServiceProvider.
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {
                //Import the RSA Key information. This needs
                //to include the private key information.
                RSA.ImportParameters(RSAKeyInfo);

                //Decrypt the passed byte array and specify OAEP padding.  
                //OAEP padding is only available on Microsoft Windows XP or
                //later.  
                decryptedData = RSA.Decrypt(DataToDecrypt, DoOAEPPadding);
            }
            return decryptedData;
        }
        //Catch and display a CryptographicException  
        //to the console.
        catch (CryptographicException e)
        {
            Console.WriteLine(e.ToString());

            return null;
        }*/

        //lets take a new CSP with a new 2048 bit rsa key pair
        var csp = new RSACryptoServiceProvider(2048);
        //how to get the private key
        var privKey = csp.ExportParameters(true);
        //and the public key ...
        var pubKey = csp.ExportParameters(false);
        //converting the public key into a string representation
        string pubKeyString;
        {
            //we need some buffer
            var sw = new System.IO.StringWriter();
            //we need a serializer
            var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            //serialize the key into the stream
            xs.Serialize(sw, pubKey);
            //get the string from the stream
            pubKeyString = sw.ToString();
        }
        //converting it back
        {
            //get a stream from the string
            var sr = new System.IO.StringReader(pubKeyString);
            //we need a deserializer
            var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            //get the object back from the stream
            pubKey = (RSAParameters)xs.Deserialize(sr);
        }
        //conversion for the private key is no black magic either ... omitted
        //we have a public key ... let's get a new csp and load that key
        csp = new RSACryptoServiceProvider();
        csp.ImportParameters(pubKey);

        //we need some data to encrypt
        var plainTextData = "abobгы";
        Console.WriteLine(plainTextData);

        //for encryption, always handle bytes...
        var bytesPlainTextData = System.Text.Encoding.Unicode.GetBytes(plainTextData);
        Console.WriteLine(bytesPlainTextData);

        //apply pkcs#1.5 padding and encrypt our data
        var bytesCypherText = csp.Encrypt(bytesPlainTextData, false);
        Console.WriteLine(bytesCypherText);

        //we might want a string representation of our cypher text... base64 will do
        var cypherText = Convert.ToBase64String(bytesCypherText);
        Console.WriteLine(cypherText);

        /*
         * some transmission / storage / retrieval
         *
         * and we want to decrypt our cypherText
         */

        //first, get our bytes back from the base64 string ...
        bytesCypherText = Convert.FromBase64String(cypherText);
        Console.WriteLine(bytesCypherText);

        //we want to decrypt, therefore we need a csp and load our private key
        csp = new RSACryptoServiceProvider();
        csp.ImportParameters(privKey);

        //decrypt and strip pkcs#1.5 padding
        bytesPlainTextData = csp.Decrypt(bytesCypherText, false);
        Console.WriteLine(bytesPlainTextData);

        //get our original plainText back...
        plainTextData = System.Text.Encoding.Unicode.GetString(bytesPlainTextData);
        Console.WriteLine(plainTextData);
    }
}