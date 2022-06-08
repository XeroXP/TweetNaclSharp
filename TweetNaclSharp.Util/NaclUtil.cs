using System.Text;
using System.Text.RegularExpressions;
using TweetNaclSharp.Core;

namespace TweetNaclSharp.Util
{
    public static class NaclUtil
    {
        private static void ValidateBase64(string s)
        {
            if (!Regex.IsMatch(s, @"^(?:[A-Za-z0-9+\\/]{2}[A-Za-z0-9+\/]{2})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$"))
            {
                throw new NaclException("invalid encoding");
            }
        }

        public static byte[] DecodeUTF8(string s)
        {
            var d = Encoding.UTF8.GetString(Encoding.Default.GetBytes(s));
            var b = new byte[d.Length];
            for (var i = 0; i < d.Length; i++) b[i] = (byte)d.ElementAt(i);
            return b;
        }

        public static string EncodeUTF8(byte[] arr)
        {
            var s = new List<char>();
            for (var i = 0; i < arr.Length; i++) s.Add((char)arr[i]);
            return Encoding.Default.GetString(Encoding.UTF8.GetBytes(string.Join("", s)));
        }

        public static string EncodeBase64(byte[] arr)
        {
            return Convert.ToBase64String(arr);
        }

        public static byte[] DecodeBase64(string s)
        {
            ValidateBase64(s);
            return Convert.FromBase64String(s);
        }
    }
}