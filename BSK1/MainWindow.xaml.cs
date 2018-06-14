using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Xml.Linq;
using System.Net;
using System.Text.RegularExpressions;
using System.ComponentModel;
using System.Windows.Threading;
using System.Security.Cryptography;
using System.Text;
using BSK1;

namespace BSK1
{
    
    public partial class MainWindow : Window
    {
        Aes aesHelper = Aes.Create();
        public MainWindow()
        {
            InitializeComponent();
            usersListBox.SelectionMode = SelectionMode.Multiple;
        }

      
        public static byte[] GetAnuBytes(int length)
        {
            byte[] bytes = new byte[length];
            for (int i = 0; i < length; i++)
                bytes[i] = (byte)((i + 1) % 10);
            return bytes;
                      
        }
    

        private void selectMode_Checked(object sender, RoutedEventArgs e)
        {
            if (modeECB.IsChecked == true)
                aesHelper.Mode = CipherMode.ECB;
           else if (modeCBC.IsChecked == true)
                aesHelper.Mode = CipherMode.CBC;
           else if (modeCFB.IsChecked == true)
                aesHelper.Mode = CipherMode.CFB;
           else if (modeOFB.IsChecked == true)
                aesHelper.Mode = CipherMode.OFB;
            aesHelper.Mode = CipherMode.ECB;
        }

        private void fileToEncode_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            if (openFileDialog.ShowDialog() == true)
                encodeName.Text = openFileDialog.FileName;
        }

        private void outputFileDirectoryEncode_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            if (openFileDialog.ShowDialog() == true)
                decodeName.Text = openFileDialog.FileName;
        }

        private void fileToDecode_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            if (openFileDialog.ShowDialog() == true)
                toDecodeName.Text = openFileDialog.FileName;
                EncryptionDecyptrion1.loadUsersExtension(openFileDialog.FileName, decryptionUsersList, extension_Label);
        }

        private void toDecodeName_TextChanged(object sender, TextChangedEventArgs e)
        {

        }

        private void addUser_Click(object sender, RoutedEventArgs e)
        {
            string _email = email.Text;
            string _password = password.Password;

          
            if (correctPassword(_password) == 0 && !String.IsNullOrEmpty(_email))
            {

                new Users(_email, _password);
                MessageBox.Show("New user: " + _email);
            }
        }

        public static int correctPassword(string password)
        {
            if (password.Length < 8)
            {
                MessageBox.Show("Password must be at least 8 characters long");
                return 1;
            }
            else if (!password.Any(char.IsDigit))
            {
                MessageBox.Show("Password must contain at least one digit");
                return 1;
            }
            else if (!password.Any(char.IsLetter))
            {
                MessageBox.Show("Password must contain at least one letter");
                return 1;
            }
            else if (!password.Any(ch => !char.IsLetterOrDigit(ch)))
            {
                MessageBox.Show("Password must contain at least one special character");
                return 1;
            }

            return 0;
        }

        private void outputFileDirectoryDecode_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            if (openFileDialog.ShowDialog() == true)
                outputFileName.Text = openFileDialog.FileName;

        }
        private static byte[] generateSessionKey(int size)
        {
            var rnd = new RNGCryptoServiceProvider();
            var key = new byte[size];
            rnd.GetBytes(key);
            return key;
        }

        private void generateRSAkey_Click(object sender, RoutedEventArgs e)
        {
            EncryptionDecyptrion1.key = generateSessionKey(Int32.Parse(keySize_TextBox.Text) / 8); //? 
            encode.IsEnabled = true;
        }


        private void encode_Click(object sender, RoutedEventArgs e)
        {
     
            try
            {
                EncryptionDecyptrion1.targetUsers = usersListBox.Items.Cast<Users>().ToList(); //lista odbiorcow pliku
                EncryptionDecyptrion1.mode = aesHelper.Mode;
                EncryptionDecyptrion1.keySize = Int32.Parse(keySize_TextBox.Text);
                EncryptionDecyptrion1.bufferSize = 1 << 15;
                EncryptionDecyptrion1.blockSize = Int32.Parse(blockSize_TextBox.Text);
                EncryptionDecyptrion1.iv = GetAnuBytes(16);

                EncryptionDecyptrion1.InitializeEncryption(encodeName.Text, decodeName.Text);
            }
            catch (Exception ex)
            {
                
            }
        }

  
        private void addUsers_Click(object sender, RoutedEventArgs e)
        {
            new AllUsers(usersListBox).Show();

        }

        private void decode_Click(object sender, RoutedEventArgs e)
        {

            try
            {
                EncryptionDecyptrion1.bufferSize = 1 << 15;
              
                Users selectedUser = (Users)decryptionUsersList.SelectedItem;
                if (selectedUser == null)
                {
                    MessageBox.Show("A user was not chosen");
                    return;
                }
                string password = decryptionPassword.Password;

                EncryptionDecyptrion1.InitializeDecryption(toDecodeName.Text, outputFileName.Text, selectedUser, password);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error encountered during decryption");
            }
        }
        private void blockSize_TextBox_PreviewTextInput(object sender, System.Windows.Input.TextCompositionEventArgs e)
        {
            e.Handled = ((TextBox)sender).Text.Length >= 3;
        }

        private void keySize_TextBox_PreviewTextInput(object sender, System.Windows.Input.TextCompositionEventArgs e)
        {
            e.Handled =  ((TextBox)sender).Text.Length >= 3;
        }
    }
    
}
