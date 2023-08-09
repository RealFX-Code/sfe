using System.Text;
using System.Security.Cryptography;

class SFE_file
{
    public string file_path = "/dev/null";

    private string encryption_iv = "sfe-aes-iv-12345";

    // 48-byte long header to insert at the start of a file.
    // Offset 0x00 -> 0x02 | generic header
    // Offset 0x03 -> 0x0A | Size of the unencrypted file in Bytes (UInt64)
    // Offset 0x0E         | Denotes what type the file is ( 0x01 = Encrypted with a password, 0x02 = Encrypted without a password )
    // Offset 0x0F         | a 0xFF byte to denote the end of the first info block.
    // Offset 0x10 -> 0x1F | If password is left empty, this will store a generic 8-byte password used to encrypt the files.
    // Offset 0x20 -> 0x2F | Denotes the start of the encrypted file
    private byte[] custom_header = {
    //   00    01    02    03    04    05    06    07    08    09    0A    0B    0C    0D    0E    0F
        0x53, 0x46, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 16 password bytes here
        0xFF, 0x57, 0x46, 0x70, 0xf1, 0x1E, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xFF
    };

    // 16-byte long footer for the file, contains no information.
    private byte[] custom_footer = {
        0x53, 0x46, 0x45, 0x00, 0x20, 0x00, 0x45, 0x4E, 0x44, 0x2D, 0x46, 0x49, 0x4C, 0x45, 0x00, 0xff
    };

    // Header and Footer both add up to 64 bytes.

    public bool store_password_in_header = false;

    private byte[] _password = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };

    public void set_encryption_password(byte[] password) {
        if(password.Length == 0) {
            Random random = new Random();
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            string str_password;
            str_password = new string(Enumerable.Repeat(chars, 16)
                .Select(s => s[random.Next(s.Length)]).ToArray());
            store_password_in_header = true;
            password = Encoding.UTF8.GetBytes(str_password);
        }
        this._password = password;
    }

    private byte[] generate_header(byte[] password, bool store_password, UInt64 file_size)
    {
        byte[] _header = custom_header;

        // init a value for byte insertion
        int offset = 0x00;

        if (store_password_in_header)
        {
            offset = 0x10;
            for (int i = offset; i <= 0x1F && i < _header.Length; i++)
            {
                byte modifiedValue = 0x00;
                if (password[i - offset] == 0x00)
                {
                    modifiedValue = 0x00;
                }
                else
                {
                    modifiedValue = password[i - offset];
                }
                _header[i] = modifiedValue;
            }
        }

        // Put file length into header
        offset = 0x03; // Offset from which you want to start reading and changing data

        byte[] _byte_file_size = BitConverter.GetBytes(file_size);

        for (int i = offset; i <= 0x0A && i < _header.Length; i++)
        {
            byte modifiedValue = _byte_file_size[i - offset];
            _header[i] = modifiedValue;
        }

        // Set the flag to denote if the password is stored in the file or not.
        if (store_password_in_header)
        {
            _header[0x0E] = 0x02; // specifies in the file that it uses a auto-generated password
        }
        else
        {
            _header[0x0E] = 0x01;
        }

        return _header;
    }

    private byte[] create_file(byte[] header, byte[] file, byte[] footer, byte[] password)
    {
        byte[] file_encrypted = encrypt(file);
        int total_length = header.Length + file_encrypted.Length + footer.Length;
        byte[] combined_file = new byte[total_length];
        int index = 0;
        Array.Copy(header, 0, combined_file, index, header.Length);
        index += header.Length;
        Array.Copy(file_encrypted, 0, combined_file, index, file_encrypted.Length);
        index += file_encrypted.Length;
        Array.Copy(footer, 0, combined_file, index, footer.Length);
        index += footer.Length;
        return combined_file;
    }

    private byte[] encrypt(byte[] file_content)
    {
        byte[] iv = Encoding.Default.GetBytes(encryption_iv);
        byte[] array;

        string file_content_b64 = Convert.ToBase64String(file_content);

        using (Aes aes = Aes.Create())
        {
            aes.Key = _password;
            aes.IV = iv;
            ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter streamWriter = new StreamWriter((Stream)cryptoStream))
                    {
                        streamWriter.Write(file_content_b64);
                    }
                    array = memoryStream.ToArray();
                }
            }
        }

        return array;
    }

    private byte[] decrypt(byte[] encrypted_file)
    {
        byte[] iv = Encoding.Default.GetBytes(encryption_iv);
        byte[] buffer = encrypted_file;
        using (Aes aes = Aes.Create())
        {
            aes.Key = _password;
            aes.IV = iv;
            ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            using (MemoryStream memoryStream = new MemoryStream(buffer))
            {
                using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader streamReader = new StreamReader((Stream)cryptoStream))
                    {
                        return Convert.FromBase64String(streamReader.ReadToEnd());
                    }
                }
            }
        }
    }

    private static byte calculateCheckSum(byte[] byteData)
	{
		Byte chkSumByte = 0x00;
		for (int i = 0; i < byteData.Length; i++)
			chkSumByte ^= byteData[i];
		return chkSumByte;
	}

    public void print_file_contents()
    {
        byte[] _file_contents = File.ReadAllBytes(file_path);
        byte[] sample_password = {
            0x70, 0x61, 0x73, 0x73, 0x77, 0x6F, 0x72, 0x64, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
        };
        byte[] header = generate_header(_password, false, Convert.ToUInt64(_file_contents.Length));
        Console.WriteLine("Raw File:");
        Console.WriteLine(Convert.ToHexString(_file_contents));
        Console.WriteLine("Custom SFE Header:");
        Console.WriteLine(Convert.ToHexString(header));
        Console.WriteLine("Custom SFE Footer:");
        Console.WriteLine(Convert.ToHexString(custom_footer));
        Console.WriteLine("Password:");
        Console.WriteLine(Convert.ToHexString(_password));
        Console.WriteLine("Password (ascii):");
        Console.WriteLine(Encoding.Default.GetString(_password));
        Console.WriteLine("AES IV:");
        Console.WriteLine(encryption_iv);
        Console.WriteLine("Encrypted file:");
        Console.WriteLine(Convert.ToHexString(encrypt(_file_contents)));
        Console.WriteLine("Full File:");
        Console.WriteLine(Convert.ToHexString(create_file(header, _file_contents, custom_footer, _password)));
        Console.WriteLine("Full File De-Crypted: ");
        Console.WriteLine(Convert.ToHexString(decrypt(encrypt(_file_contents))));
        try {
            using (var fs = new FileStream("./test/result", FileMode.Create, FileAccess.Write))
            {
                byte[] finished_file = create_file(header, _file_contents, custom_footer, _password);
                Console.WriteLine("Checksum: " + calculateCheckSum(finished_file));
                fs.Write(finished_file, 0, finished_file.Length);
            }
        } catch (Exception ex) {
            Console.WriteLine(ex);
        }
    }

    /// <summary>
    /// Encrypts a file with the given password, and stores it in "{given_file}.sfef"
    /// If no password is given it makes a unique 16-letter long string of random alphanumeric caracters.
    /// </summary>
    public void encrypt_file(string password)
    {
        byte[] byte_password = Encoding.Default.GetBytes(password);
        if (password != "") {
            if( byte_password.Length != 16) {
                byte[] fixedSizeArray = new byte[16];
                // Copy the source array into the fixed size array
                int bytesToCopy = Math.Min(byte_password.Length, 16);
                Buffer.BlockCopy(byte_password, 0, fixedSizeArray, 0, bytesToCopy);
                // Fill the remaining bytes with 0x00
                for (int i = bytesToCopy; i < 16; i++)
                {
                    fixedSizeArray[i] = 0x00;
                }
                byte_password = fixedSizeArray;
            }
        }
        Console.WriteLine("password: " + Convert.ToHexString(byte_password));
        this.set_encryption_password(byte_password);


        byte[] _file_contents = File.ReadAllBytes(file_path);
        byte[] header = generate_header(_password, store_password_in_header, Convert.ToUInt64(_file_contents.Length));

        byte[] _encrypted_file = encrypt(_file_contents);
        Console.WriteLine("Encrypting file: ", file_path);

        try {
            using (var fs = new FileStream(file_path+".sfef", FileMode.Create, FileAccess.Write))
            {
                byte[] finished_file = create_file(header, _file_contents, custom_footer, _password);
                Console.WriteLine("Checksum: " + calculateCheckSum(finished_file));
                fs.Write(finished_file, 0, finished_file.Length);
            }
        } catch (Exception ex) {
            Console.WriteLine(ex);
        }
    }
    
    public void decrypt_file(string password) {
        byte[] byte_password = Encoding.Default.GetBytes(password);
        if (password != "") {
            if( byte_password.Length != 16) {
                byte[] fixedSizeArray = new byte[16];
                // Copy the source array into the fixed size array
                int bytesToCopy = Math.Min(byte_password.Length, 16);
                Buffer.BlockCopy(byte_password, 0, fixedSizeArray, 0, bytesToCopy);
                // Fill the remaining bytes with 0x00
                for (int i = bytesToCopy; i < 16; i++)
                {
                    fixedSizeArray[i] = 0x00;
                }
                byte_password = fixedSizeArray;
            }
        }

        byte[] header_array = new byte[48]; // Your destination byte array
        byte[] footer_array = new byte[16];
        byte[] file_contents = File.ReadAllBytes(file_path);

        // Remove header from file.
        Console.WriteLine("[ii] Moving header to seperate array");
        // Copy 48 bytes from file_contents to header_array
        Buffer.BlockCopy(file_contents, 0, header_array, 0, 48);

        // Remove the copied bytes from file_contents
        Array.Copy(file_contents, 48, file_contents, 0, file_contents.Length - 48);
        Array.Resize(ref file_contents, file_contents.Length - 48);

        // Remove footer from file.
        Console.WriteLine("[ii] Moving footer to seperate array");
        // Copy the last 16 bytes from file_contents to footer_array
        Buffer.BlockCopy(file_contents, file_contents.Length - 16, footer_array, 0, 16);

        // Remove the copied bytes from file_contents
        Array.Resize(ref file_contents, file_contents.Length - 16);

        // Check if password is stored in the file

        if ( header_array[0x0E] == 0x02 ) {
            Console.WriteLine("[ii] Password is stored in the file!");

            int offset = 0x10;  // Starting offset
            int length = 0x20 - offset;  // Length of the range
            
            // Create a new byte array to store the range
            byte[] password_from_header = new byte[length];
            
            // Copy the specified range of bytes from the original array to the new array
            Array.Copy(header_array, offset, password_from_header, 0, length);

            this.set_encryption_password(password_from_header);
            byte[] decrypted_file = decrypt(file_contents);

            try {
                string _file_path = file_path.Replace(".sfef","");
                if ( File.Exists(_file_path)) {
                    _file_path = file_path.Replace(".sfef",".out");
                }
                using (var fs = new FileStream(_file_path, FileMode.Create, FileAccess.Write))
                {
                    fs.Write(decrypted_file, 0, decrypted_file.Length);
                }
            } catch (Exception ex) {
                Console.WriteLine("Exception: " + ex);
            }

        } else {
            // Password isn't stored in the file.
            if (password == "") {
                Console.WriteLine("[xx] Password isn't stored in the file, you can't have an empty password!");
                return;
            }
            this.set_encryption_password(byte_password);
            byte[] decrypted_file = decrypt(file_contents);

            try {
                string _file_path = file_path.Replace(".sfef","");
                if ( File.Exists(_file_path)) {
                    _file_path = file_path.Replace(".sfef",".out");
                }
                using (var fs = new FileStream(_file_path, FileMode.Create, FileAccess.Write))
                {
                    fs.Write(decrypted_file, 0, decrypted_file.Length);
                }
            } catch (Exception ex) {
                Console.WriteLine("Exception: " + ex);
            }
        }

    }
}

class SFE
{
    static void write_help()
    {
        Console.WriteLine("Simple File Encryptor !");
        Console.WriteLine(" - Encrypt and decrypt files, irrecoverably!");
        Console.WriteLine("Usage:");
        Console.WriteLine(" sfe -e <file>                       | Encrypts a file with a password you will be promted for.");
        Console.WriteLine(" sfe -ewp <file> <password>          | Encrypts a file with the specified password");
        Console.WriteLine(" sfe -d <file>                       | De-Crypts a file with the output specified.");
        Console.WriteLine(" sfe -dwp <file> <password>          | De-Crypts a file with the specified password.");
        Console.WriteLine(" sfe -dnp <file>                     | De-Crypts the file without a password. (only works on files encrypted without a password.)");
        Console.WriteLine("Debug/Scary Arguments:");
        Console.WriteLine(" sfe -r <file>                       | Dump out the hex data of the specified file.");
        Console.WriteLine(" sfe -dh                             | Dumps the header used for the current version of SFE.");
    }

    static void read_file(string file_path)
    {
        SFE_file sfe_file = new SFE_file();

        byte[] password = {
            0x70, 0x61, 0x73, 0x73, 0x77, 0x6F, 0x72, 0x64, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
        };

        sfe_file.file_path = file_path;
        sfe_file.set_encryption_password(password);
        sfe_file.print_file_contents();
    }

    static void encrypt_file(string file_path, string password)
    {
        SFE_file sfe_file = new SFE_file();
        sfe_file.file_path = file_path;
        sfe_file.encrypt_file(password);
    }

    static void decrypt_file(string file_path, string password)
    {
        SFE_file sfe_file = new SFE_file();
        sfe_file.file_path = file_path;
        sfe_file.decrypt_file(password);
    }

    static void Main(string[] args)
    {
        if (args.Length >= 2)
        {
            if (args[0] == "-e")
            {
                Console.WriteLine("Encrypting file: " + args[1]);
                Console.WriteLine("Your password will be cut to 16 characters.");
                Console.Write("Encrpt file with password: ");
                string? password = Console.ReadLine();
                if (password != null)
                {
                    SFE.encrypt_file(args[1], password);
                }
                else
                {
                    throw new Exception("password is null");
                }
                return;
            }
            else if (args[0] == "-d")
            {
                Console.WriteLine("Decrypting file: " + args[1]);
                Console.WriteLine("For file encrypted without a password, Just hit enter without entering a password.");
                Console.WriteLine("Your password will be cut to 16 characters.");
                Console.Write("Decrypt file with password: ");
                string? password = Console.ReadLine();
                if (password != null)
                {
                    SFE.decrypt_file(args[1], password);
                }
                else
                {
                    throw new Exception("password is null");
                }
                return;
            }
            else if (args[0] == "-r")
            {
                Console.WriteLine("Reading file: " + args[1]);
                SFE.read_file(args[1]);
                return;
            }
        }
        SFE.write_help();
    }
}