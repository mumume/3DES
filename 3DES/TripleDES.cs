using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace _3DES
{
    class TripleDES
    {
        bool[] main_key;
        bool[] permutedKey;
        bool[][] keys;
        int[][] Sbox1, Sbox2, Sbox3, Sbox4, Sbox5, Sbox6, Sbox7, Sbox8;

        public TripleDES()
        {
            GenerateSboxes();
        }

        public byte[] Encrypt(byte[] input_data, byte[] input_key)
        {
            if (input_key.Length != 24)
            {
                throw new Exception("Key length has to be 24 bytes");
            }
            byte[] output = new byte[input_data.Length];
            output = DESEncrypt(input_data, input_key.Take(8).ToArray());
            output = DESDecrypt(output, input_key.Skip(8).Take(8).ToArray());
            output = DESEncrypt(output, input_key.Skip(16).Take(8).ToArray());
            return output;
        }

        public byte[] Decrypt(byte[] input_data, byte[] input_key)
        {
            if (input_key.Length != 24)
            {
                throw new Exception("Key length has to be 24 bytes");
            }
            byte[] output = new byte[input_data.Length];            
            output = DESDecrypt(input_data, input_key.Skip(16).Take(8).ToArray());
            output = DESEncrypt(output, input_key.Skip(8).Take(8).ToArray());
            output = DESDecrypt(output, input_key.Take(8).ToArray());
            return output;
        }

        private byte[] DESEncrypt(byte[] input_data, byte[] input_key)
        {
            Console.WriteLine("Encrypting");
            List<bool> d = new List<bool>(input_data.Length * 8);
            for (int i = 0; i < input_data.Length; i++)
            {
                d.AddRange(ByteToBits(input_data[i], 8).ToList());
            }
            // add trailing zeros to fit in 64 blocks
            if (input_data.Length % 8 != 0)
            {

                for (int i = 0; i < 8 - (input_data.Length % 8); i++)
                {
                    d.AddRange(ByteToBits(0, 8).ToList());
                }
            }
            bool[] data = d.ToArray();
            byte[] output = new byte[data.Length/8];
            List<bool> key = new List<bool>(input_key.Length);
            for (int i = 0; i < 8; i++)
            {
                key.AddRange(ByteToBits(input_key[i], 8).ToList());
            }
            this.main_key = key.ToArray();
            //preparing keys
            PC1Permutation();
            KeyGeneration();
            // encryption
            bool[] encrypted = new bool[data.Length];
            for (int i = 0; i < data.Length-1; i += 64)
            {
                bool[] temp = new bool[64];
                Array.Copy(data, i, temp, 0, 64);
                temp = InitialPermutation(temp);
                temp = Cipher(temp);
                for (int n = 0; n < 8; n++)
                {
                    bool[] one_byte = new bool[8];
                    Array.Copy(temp, n * 8, one_byte, 0, 8);
                    output[i / 64 * 8 + n] = Convert.ToByte(BoolArrayToInt(one_byte));
                }
            }
            return output;
        }

        private byte[] DESDecrypt(byte[] input_data, byte[] input_key)
        {
            Console.WriteLine("Decrypting");
            List<bool> d = new List<bool>(input_data.Length * 8);
            for (int i = 0; i < input_data.Length; i++)
            {
                d.AddRange(ByteToBits(input_data[i], 8).ToList());
            }

            bool[] data = d.ToArray();
            byte[] output = new byte[data.Length / 8];
            List<bool> key = new List<bool>(input_key.Length);
            for (int i = 0; i < 8; i++)
            {
                key.AddRange(ByteToBits(input_key[i], 8).ToList());
            }
            this.main_key = key.ToArray();
            // preparing keys
            PC1Permutation();
            KeyGeneration();
            // decryption
            bool[] decrypted = new bool[data.Length];
            for (int i = 0; i < data.Length-1; i += 64)
            {
                bool[] temp = new bool[64];
                Array.Copy(data, i, temp, 0, 64);
                temp = InitialPermutation(temp);
                temp = ReverseCipher(temp);
                for (int n = 0; n < 8; n++)
                {
                    bool[] one_byte = new bool[8]; 
                    Array.Copy(temp, n * 8, one_byte, 0, 8);
                    output[i / 64 * 8 + n] = Convert.ToByte(BoolArrayToInt(one_byte));
                }
            }
            // remove trailing zeros
            for (int i = output.Length; i < output.Length - 8; i--)
            {
                if (output.ElementAt(i) == 0x00)
                {
                    Array.Copy(output, output, output.Length - 1);
                }
            }
            return output;

        }

        private bool[] Cipher(bool[] data)
        {
            bool[] Ln = data.Take(32).ToArray();
            bool[] Rn = data.Skip(32).Take(32).ToArray();
            for (int i = 0; i < 16; i++)
            {
                bool[] temp = new bool[32];
                Ln.CopyTo(temp, 0);
                bool[] func = FunctionF(Rn, i);
                Rn.CopyTo(Ln, 0);

                for (int j = 0; j < Rn.Length; j++)
                {
                    Rn[j] = temp[j] ^ func[j];
                }
            }
            bool[] encrypted = new bool[64];
            encrypted = InversePermutation(Rn.Concat(Ln).ToArray());
            return encrypted;
        }

        private bool[] ReverseCipher(bool[] data)
        {
            bool[] Ln = data.Take(32).ToArray();
            bool[] Rn = data.Skip(32).Take(32).ToArray();
            for (int i = 0; i < 16; i++)
            {
                bool[] temp = new bool[32];
                Ln.CopyTo(temp, 0);
                bool[] func = FunctionF(Rn, 15 - i);
                Rn.CopyTo(Ln, 0);

                for (int j = 0; j < Rn.Length; j++)
                {
                    Rn[j] = temp[j] ^ func[j];
                }
            }
            bool[] encrypted = new bool[64];
            encrypted = InversePermutation(Rn.Concat(Ln).ToArray());
            return encrypted;
        }

        private void GenerateSboxes()
        {
            Sbox1 = new int[4][];
            Sbox1[0] = new int[16] { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 };
            Sbox1[1] = new int[16] { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 };
            Sbox1[2] = new int[16] { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 };
            Sbox1[3] = new int[16] { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 };

            Sbox2 = new int[4][];
            Sbox2[0] = new int[16] { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 };
            Sbox2[1] = new int[16] { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 };
            Sbox2[2] = new int[16] { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 };
            Sbox2[3] = new int[16] { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 };

            Sbox3 = new int[4][];
            Sbox3[0] = new int[16] { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 };
            Sbox3[1] = new int[16] { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 };
            Sbox3[2] = new int[16] { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 };
            Sbox3[3] = new int[16] {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 };

            Sbox4 = new int[4][];
            Sbox4[0] = new int[16] { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 };
            Sbox4[1] = new int[16] { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 };
            Sbox4[2] = new int[16] { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 };
            Sbox4[3] = new int[16] { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 };

            Sbox5 = new int[4][];
            Sbox5[0] = new int[16] { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 };
            Sbox5[1] = new int[16] { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 };
            Sbox5[2] = new int[16] { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 };
            Sbox5[3] = new int[16] { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 };

            Sbox6 = new int[4][];
            Sbox6[0] = new int[16] { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 };
            Sbox6[1] = new int[16] { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 };
            Sbox6[2] = new int[16] { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 };
            Sbox6[3] = new int[16] { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 };

            Sbox7 = new int[4][];
            Sbox7[0] = new int[16] { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 };
            Sbox7[1] = new int[16] { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 };
            Sbox7[2] = new int[16] { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 };
            Sbox7[3] = new int[16] { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 };

            Sbox8 = new int[4][];
            Sbox8[0] = new int[16] { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 };
            Sbox8[1] = new int[16] { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 };
            Sbox8[2] = new int[16] { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 };
            Sbox8[3] = new int[16] { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 };
        }
        
        private bool[] FunctionF(bool[] Rn, int key_index)
        {
            bool[] ESelection = F(Rn, key_index);
            ESelection = SboxSubstition(ESelection);
            ESelection = P_Permutation(ESelection);
            return ESelection;
        }

        private bool[] F(bool[] Rn, int key_index)
        {
            bool[] ESelection = new bool[48];
            int index = 31;
            for (int i = 0; i < 48; i++)
            {
                ESelection[i] = Rn[index];
                ESelection[i] ^= keys[key_index][i];
                if ((i + 1) % 6 == 0)
                {
                    index -= 1;
                }
                else
                {
                    index = (index + 1) % 32;
                }
            }
            return ESelection;
        }

        private bool[] P_Permutation(bool[] array)
        {
            bool[] permuted = new bool[32];
            permuted[0] = array[15];
            permuted[1] = array[6];
            permuted[2] = array[19];
            permuted[3] = array[20];
            permuted[4] = array[28];
            permuted[5] = array[11];
            permuted[6] = array[27];
            permuted[7] = array[16];
            permuted[8] = array[0];
            permuted[9] = array[14];
            permuted[10] = array[22];
            permuted[11] = array[25];
            permuted[12] = array[4];
            permuted[13] = array[17];
            permuted[14] = array[30];
            permuted[15] = array[9];
            permuted[16] = array[1];
            permuted[17] = array[7];
            permuted[18] = array[23];
            permuted[19] = array[13];
            permuted[20] = array[31];
            permuted[21] = array[26];
            permuted[22] = array[2];
            permuted[23] = array[8];
            permuted[24] = array[18];
            permuted[25] = array[12];
            permuted[26] = array[29];
            permuted[27] = array[5];
            permuted[28] = array[21];
            permuted[29] = array[10];
            permuted[30] = array[3];
            permuted[31] = array[24];
            return permuted;
        }

        private bool[] SboxSubstition(bool[] array)
        {
            bool[] B = new bool[6];
            IEnumerable<bool> output = new List<bool>();
            int[] x = new int[8];
            int[] y = new int[8];
            for (int i = 0; i < 8; i++)
            {
                Array.Copy(array, i * 6, B, 0, 6);
                x[i] = BoolArrayToInt(new bool[] { B[0], B[5] });
                y[i] = BoolArrayToInt(new bool[] { B[1], B[2], B[3], B[4] });
            }


            output = output.Concat(ByteToBits(Sbox1[x[0]][y[0]], 4));
            output = output.Concat(ByteToBits(Sbox2[x[1]][y[1]], 4));
            output = output.Concat(ByteToBits(Sbox3[x[2]][y[2]], 4));
            output = output.Concat(ByteToBits(Sbox4[x[3]][y[3]], 4));
            output = output.Concat(ByteToBits(Sbox5[x[4]][y[4]], 4));
            output = output.Concat(ByteToBits(Sbox6[x[5]][y[5]], 4));
            output = output.Concat(ByteToBits(Sbox7[x[6]][y[6]], 4));
            output = output.Concat(ByteToBits(Sbox8[x[7]][y[7]], 4));
            return output.ToArray();
        }

        private int BoolArrayToInt(bool[] array)
        {
            int output = 0;
            for (int i = 0; i < array.Length; i++ )
            {
                output += Convert.ToInt16(array[i]) * (int)Math.Pow(2, array.Length - 1 -i);
            }

            return output;
        }

        private void PC1Permutation()
        {
            int index = 57;
            permutedKey = new bool[56];
            for (int i = 0; i < 56; i++)
            {
                permutedKey[i] = main_key[index - 1];
                index -= 8;
                if (index == -7 || index == -6 || index == -5)
                    index += 65;
                else if (index == 28)
                    index = 63;
                else if (index == -1 || index == -2)
                    index += 63;
                else if (index == -3)
                    index = 28;
            }
        }

        private void KeyGeneration()
        {
            keys = new bool[16][];
            bool[] Cn = permutedKey.Take(28).ToArray();
            bool[] Dn = permutedKey.Skip(28).Take(28).ToArray();            
            for (int i = 0; i < 16; i++)
            {
                if (i == 0 || i == 1 || i == 8 || i == 15)
                {
                    Cn = LeftShift(Cn);
                    Dn = LeftShift(Dn);
                } else
                {
                    Cn = DoubleLeftShift(Cn);
                    Dn = DoubleLeftShift(Dn);
                }
                keys[i] = PC2Permutation(Cn.Concat(Dn).ToArray()); 
            }
        }

        private bool[] PC2Permutation(bool[] array)
        {
            bool[] permutedArray = new bool[48];
            permutedArray[0] = array[13];
            permutedArray[1] = array[16];
            permutedArray[2] = array[10];
            permutedArray[3] = array[23];
            permutedArray[4] = array[0];
            permutedArray[5] = array[4];
            permutedArray[6] = array[2];
            permutedArray[7] = array[27];
            permutedArray[8] = array[14];
            permutedArray[9] = array[5];
            permutedArray[10] = array[20];
            permutedArray[11] = array[9];
            permutedArray[12] = array[22];
            permutedArray[13] = array[18];
            permutedArray[14] = array[11];
            permutedArray[15] = array[3];
            permutedArray[16] = array[25];
            permutedArray[17] = array[7];
            permutedArray[18] = array[15];
            permutedArray[19] = array[6];
            permutedArray[20] = array[26];
            permutedArray[21] = array[19];
            permutedArray[22] = array[12];
            permutedArray[23] = array[1];
            permutedArray[24] = array[40];
            permutedArray[25] = array[51];
            permutedArray[26] = array[30];
            permutedArray[27] = array[36];
            permutedArray[28] = array[46];
            permutedArray[29] = array[54];
            permutedArray[30] = array[29];
            permutedArray[31] = array[39];
            permutedArray[32] = array[50];
            permutedArray[33] = array[44];
            permutedArray[34] = array[32];
            permutedArray[35] = array[47];
            permutedArray[36] = array[43];
            permutedArray[37] = array[48];
            permutedArray[38] = array[38];
            permutedArray[39] = array[55];
            permutedArray[40] = array[33];
            permutedArray[41] = array[52];
            permutedArray[42] = array[45];
            permutedArray[43] = array[41];
            permutedArray[44] = array[49];
            permutedArray[45] = array[35];
            permutedArray[46] = array[28];
            permutedArray[47] = array[31];
            return permutedArray;
        }

        private bool[] InversePermutation(bool[] array)
        {
            bool[] output = new bool[64];
            int index1 = 39;
            int index2 = 7;
            for (int i  = 0; i < array.Length; i += 2)
            {
                output[i] = array[index1];
                output[i + 1] = array[index2];

                if (index1 + 8 > 64)
                {
                    index1 -= 25;
                    index2 -= 25;
                }
                else
                {
                    index1 += 8;
                    index2 += 8;
                }
            }
            return output;
        }

        private bool[] InitialPermutation(bool[] data)
        {
            int bit_number = 6;
            bool[] permutated_data = new bool[64];
            for (int i = 0; i < 8; i++)
            {
                for(int j = 0; j < 8; j++)
                {
                    permutated_data[i * 8 + j] = data[(8 - j) * 8 - bit_number - 1];
                }
                bit_number -= 2;
                if (bit_number < 0)
                    bit_number = 7;
            }
            return permutated_data;
        }

        private T[] LeftShift<T>(T[] array)
        {
            T[] temp = new T[array.Length];
            Array.Copy(array, 1, temp, 0, array.Length - 1);
            temp[array.Length - 1] = array[0];
            return temp;
        }

        private T[] DoubleLeftShift<T>(T[] array)
        {
            T[] temp = new T[array.Length];
            Array.Copy(array, 2, temp, 0, array.Length - 2);
            temp[array.Length - 2] = array[0];
            temp[array.Length - 1] = array[1];
            return temp;
        }

        private bool[] ByteToBits(int b, int outputLength)
        {
            bool[] a = new bool[outputLength];
            for (int i = 1; b > 0; i++)
            {
                a[outputLength - i] = (b % 2 == 0) ? false : true;
                b = b / 2;
            }
            return a;
        }
    }
}
