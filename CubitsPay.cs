using System;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace CubitsPay
{
	class API
	{
		public static string cubits_key;
		public static string cubits_secret;
		public static string cubits_url = "https://pay.cubits.com";
		public static HttpWebRequest request;

		/*
		 * Seting all important request headers and additional information
		 */
		public static void setup_request(string host, string path, string key, string secret){
			cubits_key = key;
			cubits_secret = secret;
			request = (HttpWebRequest)WebRequest.Create(host + path);
			request.Accept = "application/vnd.api+json";
			request.Headers["X-Cubits-Key"] = cubits_key;
			string nonce = calc_nonce();
			request.Headers["X-Cubits-Nonce"] = nonce;
			request.Headers["X-Cubits-Signature"] = calc_signature(path, nonce);
		}

		/*
		 * Simple nonce calculation with timestamp
		 */
		public static string calc_nonce(){
			var unixTime = DateTime.Now.ToUniversalTime() -
				new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
			return string.Format("{0}", (long)unixTime.TotalMilliseconds);
		}

		public static string calc_signature(string path, string nonce, string request_data=""){
			string sha256_msg = BitConverter.ToString(new SHA256CryptoServiceProvider().ComputeHash(Encoding.UTF8.GetBytes(request_data))).Replace("-", "").ToLower();
			string msg = string.Format("{0}{1}{2}", path, nonce, sha256_msg);
			string hmac_sha512_signature = BitConverter.ToString(new HMACSHA512(Encoding.UTF8.GetBytes(cubits_secret)).ComputeHash(Encoding.UTF8.GetBytes(msg))).Replace("-", "").ToLower();
			Console.WriteLine("Computed Msg.: {0}", msg);
			Console.WriteLine("Computed Signature: {0}", hmac_sha512_signature);
			return hmac_sha512_signature;
		}

		/*
		 * Main programm execution.
		 */
		public static void Main(string[] args)
		{
			HttpWebResponse response;
			try{
				Console.WriteLine("key: " + args[0]);
				Console.WriteLine("secret: " + args[1]);
				setup_request(cubits_url, "/api/v1/test", args[0], args[1]);
				response = (HttpWebResponse)request.GetResponse();
				Console.WriteLine("Request result: " + response.StatusCode);
			}
			catch(WebException e) {
				Console.WriteLine(" | " + e.Message);
			}
			Console.ReadKey();
		}
	}
}
