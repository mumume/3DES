using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace _3DES
{
    class Program
    {
        static void Main(string[] args)
        {
            TripleDES des = new TripleDES();
            byte[] key = new byte[] { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
               0x0e, 0x0f, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b};
            // encrypt and save the file
            string filePath = "C:\\Users\\Konrad\\source\\repos\\3DES\\movie_Trim.mp4";
            byte[] movie = File.ReadAllBytes(filePath);
            byte[] data = des.Encrypt(movie, key);
            File.WriteAllBytes("C:\\Users\\Konrad\\source\\repos\\3DES\\encrypted_file.dat", data);
            //decrypt and save the file
            data = des.Decrypt(data, key);
            File.WriteAllBytes("C:\\Users\\Konrad\\source\\repos\\3DES\\decrypted_file.txt", data);
        }
    }
}
