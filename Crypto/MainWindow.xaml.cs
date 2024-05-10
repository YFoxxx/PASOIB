using Microsoft.Win32;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Security;

namespace Crypto
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private EncryptionMethod selectedMethod;

        public enum EncryptionMethod
        {
            RSA,
            AES,
            GOST
        }

        public MainWindow()
        {
            InitializeComponent();
            // По умолчанию выбираем RSA
            rbRSA.IsChecked = true;
            selectedMethod = EncryptionMethod.RSA;
        }

        private void ChooseFile_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            if (openFileDialog.ShowDialog() == true)
            {
                txtSelectedFile.Text = openFileDialog.FileName;
            }
        }

        private void EncryptionMethod_Checked(object sender, RoutedEventArgs e)
        {
            if (rbRSA.IsChecked == true)
            {
                selectedMethod = EncryptionMethod.RSA;
            }
            else if (rbAES.IsChecked == true)
            {
                selectedMethod = EncryptionMethod.AES;
            }
            else if (rbGOST.IsChecked == true)
            {
                selectedMethod = EncryptionMethod.GOST;
            }
        }

        private void EncryptFile_Click(object sender, RoutedEventArgs e)
        {
            switch (selectedMethod)
            {
                case EncryptionMethod.RSA:
                    EncryptFileRSA();
                    break;
                case EncryptionMethod.AES:
                    EncryptFileAES();
                    break;
                case EncryptionMethod.GOST:
                    EncryptFileGOST();
                    break;
                default:
                    MessageBox.Show("Encryption method not selected.");
                    break;
            }
        }

        private void DecryptFile_Click(object sender, RoutedEventArgs e)
        {
            switch (selectedMethod)
            {
                case EncryptionMethod.RSA:
                    DecryptFileRSA();
                    break;
                case EncryptionMethod.AES:
                    DecryptFileAES();
                    break;
                case EncryptionMethod.GOST:
                    DecryptFileGOST();
                    break ;
                default:
                    MessageBox.Show("Encryption method not selected.");
                    break;
            }
        }

        private void EncryptFileGOST()
        {
            try
            {
                string selectedFilePath = txtSelectedFile.Text;
                if (!string.IsNullOrEmpty(selectedFilePath))
                {
                    // Создаем экземпляр класса для шифрования ГОСТ 28147-89
                    Gost28147Engine gostEngine = new Gost28147Engine();

                    // Генерируем случайный ключ
                    byte[] key = new byte[32];
                    SecureRandom secureRandom = new SecureRandom();
                    secureRandom.NextBytes(key);
                    // Шифруем содержимое файла
                    byte[] originalData = File.ReadAllBytes(selectedFilePath);
                    byte[] encryptedData;

                    using (MemoryStream ms = new MemoryStream())
                    {
                        IBufferedCipher cipher = CipherUtilities.GetCipher("GOST");
                        cipher.Init(true, new KeyParameter(key));

                        using (CipherStream cs = new CipherStream(ms, null, cipher))
                        {
                            cs.Write(originalData, 0, originalData.Length);
                        }
                        encryptedData = ms.ToArray();
                    }

                    // Сохраняем зашифрованные данные в файл
                    File.WriteAllBytes(selectedFilePath + ".encrypted_gost", encryptedData);

                    // Сохраняем ключ в файл
                    File.WriteAllBytes(selectedFilePath + ".gost_key", key);

                    MessageBox.Show("File encrypted successfully using GOST.");
                }
                else
                {
                    MessageBox.Show("Please choose a file to encrypt.");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Encryption error: " + ex.Message);
            }
        }

        private void DecryptFileGOST()
        {
            try
            {
                string selectedFilePath = txtSelectedFile.Text;
                string keyFilePath = selectedFilePath + ".gost_key";

                if (!string.IsNullOrEmpty(selectedFilePath) && File.Exists(keyFilePath))
                {
                    byte[] key = File.ReadAllBytes(keyFilePath);

                    // Создаем экземпляр класса для шифрования ГОСТ 28147-89
                    Gost28147Engine gostEngine = new Gost28147Engine();

                    // Расшифровываем содержимое файла
                    byte[] encryptedData = File.ReadAllBytes(selectedFilePath);
                    byte[] decryptedData;

                    using (MemoryStream ms = new MemoryStream())
                    {
                        IBufferedCipher cipher = CipherUtilities.GetCipher("GOST");
                        cipher.Init(false, new KeyParameter(key));

                        using (CipherStream cs = new CipherStream(ms, null, cipher))
                        {
                            cs.Write(encryptedData, 0, encryptedData.Length);
                        }
                        decryptedData = ms.ToArray();
                    }

                    // Удаляем расшифрованные данные из имени файла
                    string decryptedFilePath = selectedFilePath.Substring(0, selectedFilePath.LastIndexOf(".encrypted_gost"));

                    // Сохраняем расшифрованные данные в новый файл
                    File.WriteAllBytes(decryptedFilePath, decryptedData);

                    MessageBox.Show("File decrypted successfully using GOST.");
                }
                else
                {
                    MessageBox.Show("Please choose an encrypted file and make sure the decryption key is available.");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Decryption error: " + ex.Message);
            }
        }

        // Методы шифрования и расшифровки для RSA и AES
        private void EncryptFileRSA()
        {
            try
            {
                string selectedFilePath = txtSelectedFile.Text;
                if (!string.IsNullOrEmpty(selectedFilePath))
                {
                    using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                    {
                        // Получаем публичный и приватный ключи
                        string publicKey = rsa.ToXmlString(false);
                        string privateKey = rsa.ToXmlString(true);
                        // Шифруем содержимое файла
                        byte[] originalData = File.ReadAllBytes(selectedFilePath);
                        byte[] encryptedData = rsa.Encrypt(originalData, false);
                        // Сохраняем зашифрованные данные в файл
                        File.WriteAllBytes(selectedFilePath + ".encrypted", encryptedData);
                        // Записываем параметры расшифровки в шифрованный файл
                        File.WriteAllText(selectedFilePath + ".encrypted.params", privateKey);
                    }
                    MessageBox.Show("File encrypted successfully using RSA.");
                }
                else
                {
                    MessageBox.Show("Please choose a file to encrypt.");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Encryption error: " + ex.Message);
            }
        }

        private void DecryptFileRSA()
        {
            try
            {
                string selectedFilePath = txtSelectedFile.Text;
                string encryptedParamsFilePath = selectedFilePath + ".params";

                if (!string.IsNullOrEmpty(selectedFilePath) && File.Exists(encryptedParamsFilePath))
                {
                    using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                    {
                        // Получаем приватный ключ из файла параметров
                        string privateKey = File.ReadAllText(encryptedParamsFilePath);
                        rsa.FromXmlString(privateKey);

                        // Расшифровываем содержимое файла
                        byte[] encryptedData = File.ReadAllBytes(selectedFilePath);
                        byte[] decryptedData = rsa.Decrypt(encryptedData, false);

                        // Удаляем расшифрованные данные из имени файла
                        string decryptedFilePath = selectedFilePath.Substring(0, selectedFilePath.LastIndexOf(".encrypted"));

                        // Сохраняем расшифрованные данные в новый файл
                        File.WriteAllBytes(decryptedFilePath, decryptedData);
                    }
                    MessageBox.Show("File decrypted successfully using RSA.");
                }
                else
                {
                    MessageBox.Show("Please choose an encrypted file and make sure the decryption parameters are available.");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Decryption error: " + ex.Message);
            }
        }

        private void EncryptFileAES()
        {
            try
            {
                string selectedFilePath = txtSelectedFile.Text;
                if (!string.IsNullOrEmpty(selectedFilePath))
                {
                    using (Aes aes = Aes.Create())
                    {
                        // Генерируем случайный ключ и вектор инициализации
                        aes.GenerateKey();
                        aes.GenerateIV();

                        // Шифруем содержимое файла
                        byte[] originalData = File.ReadAllBytes(selectedFilePath);
                        using (MemoryStream ms = new MemoryStream())
                        {
                            // Используем режим CBC (Cipher Block Chaining)
                            using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                            {
                                cs.Write(originalData, 0, originalData.Length);
                                cs.Close();
                            }
                            byte[] encryptedData = ms.ToArray();

                            // Сохраняем зашифрованные данные в файл
                            File.WriteAllBytes(selectedFilePath + ".encrypted_aes", encryptedData);

                            // Сохраняем ключ и вектор инициализации в файл
                            File.WriteAllBytes(selectedFilePath + ".aes_key", aes.Key);
                            File.WriteAllBytes(selectedFilePath + ".aes_iv", aes.IV);
                        }
                    }
                    MessageBox.Show("File encrypted successfully using AES.");
                }
                else
                {
                    MessageBox.Show("Please choose a file to encrypt.");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Encryption error: " + ex.Message);
            }
        }

        private void DecryptFileAES()
        {
            try
            {
                string selectedFilePath = txtSelectedFile.Text;
                string keyFilePath = selectedFilePath + ".aes_key";
                string ivFilePath = selectedFilePath + ".aes_iv";

                if (!string.IsNullOrEmpty(selectedFilePath) && File.Exists(keyFilePath) && File.Exists(ivFilePath))
                {
                    byte[] key = File.ReadAllBytes(keyFilePath);
                    byte[] iv = File.ReadAllBytes(ivFilePath);

                    using (Aes aes = Aes.Create())
                    {
                        // Устанавливаем ключ и вектор инициализации
                        aes.Key = key;
                        aes.IV = iv;

                        // Расшифровываем содержимое файла
                        byte[] encryptedData = File.ReadAllBytes(selectedFilePath);
                        using (MemoryStream ms = new MemoryStream())
                        {
                            using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                            {
                                cs.Write(encryptedData, 0, encryptedData.Length);
                                cs.Close();
                            }
                            byte[] decryptedData = ms.ToArray();

                            // Удаляем расшифрованные данные из имени файла
                            string decryptedFilePath = selectedFilePath.Substring(0, selectedFilePath.LastIndexOf(".encrypted_aes"));

                            // Сохраняем расшифрованные данные в новый файл
                            File.WriteAllBytes(decryptedFilePath, decryptedData);
                        }
                    }
                    MessageBox.Show("File decrypted successfully using AES.");
                }
                else
                {
                    MessageBox.Show("Please choose an encrypted file and make sure the decryption parameters are available.");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Decryption error: " + ex.Message);
            }
        }
    }
}